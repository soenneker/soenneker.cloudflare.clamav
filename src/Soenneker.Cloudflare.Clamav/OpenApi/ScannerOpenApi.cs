using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Soenneker.Cloudflare.Clamav.Endpoints;
using Soenneker.Cloudflare.Clamav.Enums;
using Soenneker.Cloudflare.Clamav.Responses;

namespace Soenneker.Cloudflare.Clamav.OpenApi;

/// <summary>Configures the generated scanner contract for clients that upload raw files and poll scan jobs.</summary>
public static class ScannerOpenApi
{
    /// <summary>Adds service metadata, API-key security, and raw upload descriptions to the generated document.</summary>
    /// <param name="options">The options for the scanner's version-one OpenAPI document.</param>
    public static void Configure(OpenApiOptions options)
    {
        options.OpenApiVersion = OpenApiSpecVersion.OpenApi3_1;
        options.AddSchemaTransformer(TransformSchema);
        options.AddOperationTransformer(TransformOperation);
        options.AddDocumentTransformer(TransformDocument);
    }

    /// <summary>Describes uploads that read the request stream directly and assigns stable operation identifiers.</summary>
    /// <param name="operation">The endpoint operation being generated.</param>
    /// <param name="context">Metadata for the endpoint.</param>
    /// <param name="cancellationToken">The document generation cancellation token.</param>
    /// <returns>A completed task after applying operation metadata.</returns>
    private static Task TransformOperation(OpenApiOperation operation, OpenApiOperationTransformerContext context,
        CancellationToken cancellationToken)
    {
        string? name = context.Description.ActionDescriptor.EndpointMetadata.OfType<IEndpointNameMetadata>().FirstOrDefault()?.EndpointName;
        if (name is null)
            return Task.CompletedTask;

        operation.OperationId = name;
        if (operation.Responses is not null)
        {
            foreach (KeyValuePair<string, IOpenApiResponse> response in operation.Responses)
            {
                if (response.Value is not OpenApiResponse concrete || concrete.Content is null ||
                    (!concrete.Content.TryGetValue("application/json", out OpenApiMediaType? mediaType) &&
                     !concrete.Content.TryGetValue("application/problem+json", out mediaType)))
                    continue;

                string contentType = response.Key is "401" or "404" or "413" ? "application/problem+json" : "application/json";
                concrete.Content = new Dictionary<string, OpenApiMediaType> { [contentType] = mediaType };
                if (response.Key == "401")
                {
                    concrete.Content["text/plain"] = new OpenApiMediaType
                    {
                        Schema = new OpenApiSchema { Type = JsonSchemaType.String },
                        Example = JsonValue.Create("Unauthorized")
                    };
                }
            }
        }

        if (name is nameof(ScannerEndpoints.Scan) or nameof(ScannerEndpoints.Queue))
        {
            operation.RequestBody = new OpenApiRequestBody
            {
                Required = true,
                Description = "Raw file bytes, not multipart form data. The default upload limit is 100 MiB and can be configured by the operator.",
                Content = new Dictionary<string, OpenApiMediaType>
                {
                    ["application/octet-stream"] = new()
                    {
                        Schema = new OpenApiSchema { Type = JsonSchemaType.String, Format = "binary" }
                    }
                }
            };
        }

        return Task.CompletedTask;
    }

    /// <summary>Describes job identifiers and the serialized status values used by the service.</summary>
    /// <param name="schema">The response schema being generated.</param>
    /// <param name="context">The CLR type associated with the schema.</param>
    /// <param name="cancellationToken">The document generation cancellation token.</param>
    /// <returns>A completed task after applying response property metadata.</returns>
    private static Task TransformSchema(OpenApiSchema schema, OpenApiSchemaTransformerContext context,
        CancellationToken cancellationToken)
    {
        bool isJob = context.JsonTypeInfo.Type == typeof(VirusScanJobResponse);
        bool isAccepted = context.JsonTypeInfo.Type == typeof(VirusScanJobAcceptedResponse);
        if ((!isJob && !isAccepted) || schema.Properties is null)
            return Task.CompletedTask;

        if (schema.Properties.TryGetValue("id", out IOpenApiSchema? id) && id is OpenApiSchema idSchema)
            idSchema.Format = "uuid";

        if (schema.Properties.TryGetValue("status", out IOpenApiSchema? status) && status is OpenApiSchema statusSchema)
        {
            statusSchema.Enum = isAccepted ? [JsonValue.Create(VirusScanJobStatus.Queued.Value)] :
            [
                JsonValue.Create(VirusScanJobStatus.Queued.Value),
                JsonValue.Create(VirusScanJobStatus.Processing.Value),
                JsonValue.Create(VirusScanJobStatus.Completed.Value),
                JsonValue.Create(VirusScanJobStatus.Failed.Value)
            ];
        }

        return Task.CompletedTask;
    }

    /// <summary>Describes the service and applies bearer API-key authentication to scan and job operations.</summary>
    /// <param name="document">The complete generated document.</param>
    /// <param name="context">The current document generation context.</param>
    /// <param name="cancellationToken">The document generation cancellation token.</param>
    /// <returns>A completed task after applying document metadata.</returns>
    private static Task TransformDocument(OpenApiDocument document, OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        document.Info = new OpenApiInfo
        {
            Title = "Soenneker.Cloudflare.Clamav",
            Version = "v1",
            Description = "ClamAV file scanning with Cloudflare Containers and R2 job storage. Supply your deployment URL as the API base address."
        };
        document.Servers = [new OpenApiServer { Url = "/" }];
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["ScannerApiKey"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            Description = "The operator-configured Scanner:ApiKey supplied as Authorization: Bearer <key>. This is an API key, not a JWT."
        };

        foreach (KeyValuePair<string, IOpenApiPathItem> path in document.Paths)
        {
            if (path.Value.Operations is null)
                continue;

            foreach (OpenApiOperation operation in path.Value.Operations.Values)
            {
                operation.Security = path.Key == "/health" ? [] :
                [
                    new OpenApiSecurityRequirement
                    {
                        [new OpenApiSecuritySchemeReference("ScannerApiKey", document)] = []
                    }
                ];
            }
        }

        return Task.CompletedTask;
    }
}

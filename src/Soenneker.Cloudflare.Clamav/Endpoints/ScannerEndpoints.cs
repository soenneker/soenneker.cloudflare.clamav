using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Soenneker.Cloudflare.Clamav.Stores;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Soenneker.Cloudflare.Clamav.Managers.Abstract;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Utils.File.Abstract;
using Soenneker.Utils.Path.Abstract;

namespace Soenneker.Cloudflare.Clamav.Endpoints;

/// <summary>
/// Exposes ClamAV readiness, authenticated file scanning, and background job retrieval over HTTP.
/// </summary>
/// <remarks>
/// Upload endpoints accept raw request bytes rather than multipart form data. Scan and job endpoints
/// require the configured scanner API key as a bearer token; the health endpoint is unauthenticated.
/// </remarks>
public sealed class ScannerEndpoints
{
    /// <summary>Maps the scanner HTTP contract using generated Minimal API request delegates.</summary>
    /// <param name="endpoints">The application's endpoint route builder.</param>
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health", (ScannerEndpoints scanner, CancellationToken token) => scanner.Health(token))
            .WithName(nameof(Health)).WithSummary("Queries ClamAV readiness.")
            .Produces<HealthResponse>().Produces<HealthResponse>(StatusCodes.Status503ServiceUnavailable);
        endpoints.MapPost("/scan", (ScannerEndpoints scanner, HttpRequest request, CancellationToken token) => scanner.Scan(request, token))
            .WithName(nameof(Scan)).WithSummary("Accepts a raw file upload and waits for its scan verdict.")
            .Produces<VirusScanResponse>().ProducesProblem(401).ProducesProblem(413);
        endpoints.MapPost("/scan/jobs", (ScannerEndpoints scanner, HttpRequest request, CancellationToken token) => scanner.Queue(request, token))
            .WithName(nameof(Queue)).WithSummary("Accepts a raw file upload for background scanning.")
            .Produces<VirusScanJobAcceptedResponse>(202).ProducesProblem(401).ProducesProblem(413);
        endpoints.MapGet("/scan/jobs/{jobId}", (ScannerEndpoints scanner, HttpRequest request, string jobId, CancellationToken token) => scanner.GetJob(request, jobId, token))
            .WithName(nameof(GetJob)).WithSummary("Retrieves the latest persisted state of a background scan.")
            .Produces<VirusScanJobResponse>().ProducesProblem(401).ProducesProblem(404);
    }

    private const long _defaultMaximumFileSize = 100 * 1024 * 1024;
    private const string _bearerPrefix = "Bearer ";

    private readonly IScannerManager _scannerManager;
    private readonly IFileUtil _fileUtil;
    private readonly IPathUtil _pathUtil;
    private readonly long _maximumFileSize;
    private readonly string? _apiKey;

    /// <summary>
    /// Initializes the endpoint handler with its scan pipeline, temporary-file utilities, and request settings.
    /// </summary>
    /// <param name="scannerManager">The pipeline that takes ownership of uploaded files and executes scans.</param>
    /// <param name="fileUtil">The utility used to write and clean up temporary uploads.</param>
    /// <param name="pathUtil">The utility used to allocate temporary upload paths.</param>
    /// <param name="configuration">Provides <c>Scanner:ApiKey</c> and the optional <c>Scanner:MaximumFileSize</c> limit in bytes.</param>
    public ScannerEndpoints(IScannerManager scannerManager, IFileUtil fileUtil, IPathUtil pathUtil, IConfiguration configuration)
    {
        _scannerManager = scannerManager;
        _fileUtil = fileUtil;
        _pathUtil = pathUtil;
        _maximumFileSize = configuration.GetValue("Scanner:MaximumFileSize", _defaultMaximumFileSize);
        _apiKey = configuration["Scanner:ApiKey"];
    }

    /// <summary>
    /// Queries ClamAV for its version to check scanner readiness.
    /// </summary>
    /// <param name="cancellationToken">Cancels the version query.</param>
    /// <returns>HTTP 200 when version text is available, or HTTP 503 when it is empty.</returns>
    /// <remarks>This check does not verify R2 access or definition freshness. Version-query exceptions propagate.</remarks>
    public async ValueTask<IResult> Health(CancellationToken cancellationToken)
    {
        string version = await _scannerManager.GetVersion(cancellationToken);
        bool ready = !string.IsNullOrWhiteSpace(version);

        return ready
            ? TypedResults.Ok(new HealthResponse(true))
            : TypedResults.Json(new HealthResponse(false), LibraryJsonContext.Default.HealthResponse, statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// Accepts a raw file upload and waits for its scan verdict.
    /// </summary>
    /// <param name="request">The incoming HTTP request.</param>
    /// <param name="cancellationToken">Cancels upload handling, enqueueing, or waiting for the verdict.</param>
    /// <returns>HTTP 200 with the verdict, HTTP 401 for failed authentication, or HTTP 413 for an oversized upload.</returns>
    /// <remarks>
    /// The request body is written to a temporary file before ownership transfers to the scan pipeline.
    /// Disconnecting after enqueueing does not cancel the queued scan. Scan failures propagate to the HTTP pipeline.
    /// </remarks>
    public async ValueTask<IResult> Scan(HttpRequest request, CancellationToken cancellationToken)
    {
        if (!IsAuthorized(request.Headers.Authorization.ToString()))
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized);

        if (request.ContentLength.HasValue && request.ContentLength.Value > _maximumFileSize)
        {
            return TypedResults.Problem(
                statusCode: StatusCodes.Status413PayloadTooLarge,
                title: "File is too large",
                detail: $"The maximum scan size is {_maximumFileSize} bytes.");
        }

        string? temporaryPath = await WriteRequestToTemporaryFile(request, cancellationToken);

        try
        {
            string ownedPath = temporaryPath;
            temporaryPath = null;
            VirusScanResponse result = await _scannerManager.Scan(ownedPath, cancellationToken);
            return TypedResults.Ok(result);
        }
        finally
        {
            if (temporaryPath is not null)
                await _fileUtil.TryDelete(temporaryPath, log: false, CancellationToken.None);
        }
    }

    /// <summary>
    /// Accepts a raw file upload for background scanning and returns a polling location.
    /// </summary>
    /// <param name="request">The incoming HTTP request.</param>
    /// <param name="cancellationToken">Cancels upload handling, initial job persistence, or enqueueing.</param>
    /// <returns>HTTP 202 with the job identifier and status URL, HTTP 401 for failed authentication, or HTTP 413 for an oversized upload.</returns>
    /// <remarks>Acceptance persists job metadata; uploaded files and pending work remain local to the container.</remarks>
    public async ValueTask<IResult> Queue(HttpRequest request, CancellationToken cancellationToken)
    {
        if (!IsAuthorized(request.Headers.Authorization.ToString()))
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized);

        IResult? invalidRequest = ValidateFileSize(request);
        if (invalidRequest is not null)
            return invalidRequest;

        string? temporaryPath = await WriteRequestToTemporaryFile(request, cancellationToken);

        try
        {
            string ownedPath = temporaryPath;
            temporaryPath = null;
            VirusScanJobResponse job = await _scannerManager.Queue(ownedPath, cancellationToken);
            string statusUrl = $"{request.Scheme}://{request.Host}{request.PathBase}/scan/jobs/{job.Id}";
            return TypedResults.Accepted(statusUrl, new VirusScanJobAcceptedResponse(job.Id, job.Status, statusUrl));
        }
        finally
        {
            if (temporaryPath is not null)
                await _fileUtil.TryDelete(temporaryPath, log: false, CancellationToken.None);
        }
    }

    /// <summary>
    /// Retrieves the latest persisted state of a background scan.
    /// </summary>
    /// <param name="jobId">The job identifier in standard dashed GUID format.</param>
    /// <param name="request">The incoming HTTP request.</param>
    /// <param name="cancellationToken">Cancels retrieval from the job store.</param>
    /// <returns>HTTP 200 with the record, HTTP 401 for failed authentication, or HTTP 404 for an invalid or missing identifier.</returns>
    public async ValueTask<IResult> GetJob(HttpRequest request, string jobId, CancellationToken cancellationToken)
    {
        if (!IsAuthorized(request.Headers.Authorization.ToString()))
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized);

        if (!Guid.TryParseExact(jobId, "D", out _))
            return TypedResults.Problem(statusCode: StatusCodes.Status404NotFound);

        VirusScanJobResponse? job = await _scannerManager.GetJob(jobId, cancellationToken);
        return job is null ? TypedResults.Problem(statusCode: StatusCodes.Status404NotFound) : TypedResults.Ok(job);
    }

    /// <summary>Copies the raw request body into a newly allocated temporary scan file.</summary>
    /// <param name="request">The incoming HTTP request.</param>
    /// <param name="cancellationToken">Cancels path allocation or writing the upload.</param>
    /// <returns>The temporary file path, whose ownership remains with the caller until transferred to the scan pipeline.</returns>
    private async ValueTask<string> WriteRequestToTemporaryFile(HttpRequest request, CancellationToken cancellationToken)
    {
        string temporaryPath = await _pathUtil.GetRandomTempFilePath(".scan", cancellationToken);
        await _fileUtil.Write(temporaryPath, request.Body, log: false, cancellationToken);
        return temporaryPath;
    }

    /// <summary>Checks a declared content length against the configured upload limit.</summary>
    /// <param name="request">The incoming HTTP request.</param>
    /// <returns>An HTTP 413 problem result when oversized, otherwise <see langword="null"/>.</returns>
    /// <remarks>Kestrel also enforces the request body limit, including uploads without a declared length.</remarks>
    private IResult? ValidateFileSize(HttpRequest request)
    {
        if (!request.ContentLength.HasValue || request.ContentLength.Value <= _maximumFileSize)
            return null;

        return TypedResults.Problem(
            statusCode: StatusCodes.Status413PayloadTooLarge,
            title: "File is too large",
            detail: $"The maximum scan size is {_maximumFileSize} bytes.");
    }

    /// <summary>Validates the bearer prefix and compares the supplied API key using a fixed-time byte comparison.</summary>
    /// <param name="authorization">The complete Authorization header value.</param>
    /// <returns>Whether the header contains the configured, nonempty scanner API key.</returns>
    private bool IsAuthorized(string authorization)
    {
        if (string.IsNullOrWhiteSpace(_apiKey) || !authorization.StartsWith(_bearerPrefix, StringComparison.Ordinal))
            return false;

        string providedKey = authorization[_bearerPrefix.Length..];
        byte[] expectedBytes = Encoding.UTF8.GetBytes(_apiKey);
        byte[] providedBytes = Encoding.UTF8.GetBytes(providedKey);

        return CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}

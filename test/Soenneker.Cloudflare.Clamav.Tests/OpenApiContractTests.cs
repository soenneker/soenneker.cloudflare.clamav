using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;

namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Checks the generated API contract against upload, authentication, and job response behavior.</summary>
public sealed class OpenApiContractTests
{
    /// <summary>Verifies raw upload schemas, response models, XML descriptions, and the anonymous health operation.</summary>
    /// <returns>A task that completes after checking the generated contract.</returns>
    [Test]
    public async Task Generated_document_describes_scanner_contract()
    {
        await using var application = new ScannerApplicationFactory();
        await using AsyncServiceScope scope = application.Services.CreateAsyncScope();
        var provider = scope.ServiceProvider.GetRequiredKeyedService<IOpenApiDocumentProvider>("v1");
        OpenApiDocument document = await provider.GetOpenApiDocumentAsync();

        await Assert.That(document.Paths.Count).IsEqualTo(4);
        OpenApiOperation health = document.Paths["/health"].Operations!.Values.Single();
        await Assert.That(health.Security!.Count).IsEqualTo(0);
        await Assert.That(health.Responses!.ContainsKey("503")).IsTrue();

        foreach (string path in new[] { "/scan", "/scan/jobs" })
        {
            OpenApiOperation upload = document.Paths[path].Operations!.Values.Single();
            await Assert.That(upload.Security!.Count).IsEqualTo(1);
            await Assert.That(string.IsNullOrWhiteSpace(upload.Summary)).IsFalse();
            await Assert.That(upload.RequestBody!.Required).IsTrue();
            await Assert.That(upload.RequestBody.Content!["application/octet-stream"].Schema!.Format).IsEqualTo("binary");
            await Assert.That(upload.Responses!["401"].Content!.ContainsKey("text/plain")).IsTrue();
            await Assert.That(upload.Responses["413"].Content!.ContainsKey("application/problem+json")).IsTrue();
        }

        OpenApiOperation queued = document.Paths["/scan/jobs"].Operations!.Values.Single();
        await Assert.That(queued.Responses!.ContainsKey("202")).IsTrue();
        IOpenApiSchema job = document.Components!.Schemas!["VirusScanJobResponse"];
        await Assert.That(job.Properties!["status"].Enum!.Select(value => value!.ToString()).ToArray())
            .IsEquivalentTo(new[] { "queued", "processing", "completed", "failed" });
        await Assert.That(job.Properties["id"].Format).IsEqualTo("uuid");
        await Assert.That(string.IsNullOrWhiteSpace(job.Properties["createdAt"].Description)).IsFalse();
    }
}

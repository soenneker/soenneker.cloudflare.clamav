using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Http.Json;
using Soenneker.Cloudflare.Clamav.Managers.Abstract;
using Soenneker.Cloudflare.Clamav.Responses;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Verifies HTTP request validation through the scanner's real endpoints and dependency registrations.</summary>
public sealed class CloudflareClamavTests
{
    [Test]
    [Arguments("/scan")]
    [Arguments("/scan/jobs")]
    public async Task Scan_requires_authentication(string path)
    {
        await using var application = new ScannerApplicationFactory();
        using System.Net.Http.HttpClient client = application.CreateClient();
        using var content = new ByteArrayContent([1]);
        using HttpResponseMessage response = await client.PostAsync(path, content);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>Verifies that unauthenticated uploads are rejected before scanning or persistence.</summary>
    /// <param name="path">The synchronous or background upload route to exercise.</param>
    /// <returns>A task that completes after the HTTP response is checked.</returns>
    /// <summary>Verifies that authenticated uploads exceeding the configured byte limit receive HTTP 413.</summary>
    /// <param name="path">The synchronous or background upload route to exercise.</param>
    /// <returns>A task that completes after the HTTP response is checked.</returns>
    [Test]
    [Arguments("/scan")]
    [Arguments("/scan/jobs")]
    public async Task Authorized_oversized_upload_is_rejected(string path)
    {
        await using var application = new ScannerApplicationFactory();
        using System.Net.Http.HttpClient client = application.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "scanner-test-key");
        using var content = new ByteArrayContent(new byte[17]);
        using HttpResponseMessage response = await client.PostAsync(path, content);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.RequestEntityTooLarge);
    }

    /// <summary>Verifies that malformed job identifiers receive HTTP 404 before storage is queried.</summary>
    /// <returns>A task that completes after the HTTP response is checked.</returns>
    [Test]
    public async Task Invalid_job_id_is_rejected_without_querying_R2()
    {
        await using var application = new ScannerApplicationFactory();
        using System.Net.Http.HttpClient client = application.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "scanner-test-key");
        using HttpResponseMessage response = await client.GetAsync("/scan/jobs/not-a-guid");
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }
    [Test]
    public async Task Responses_use_generated_metadata_and_preserve_job_location()
    {
        await using var factory = new ScannerApplicationFactory();
        var manager = new FakeScannerManager();
        await using WebApplicationFactory<Program> application = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IScannerManager>();
            services.AddSingleton<IScannerManager>(manager);
            services.Configure<JsonOptions>(options =>
            {
                // Keep only the application's generated resolver: reflection cannot mask missing metadata.
                for (int i = options.SerializerOptions.TypeInfoResolverChain.Count - 1; i >= 0; i--)
                {
                    if (options.SerializerOptions.TypeInfoResolverChain[i] is DefaultJsonTypeInfoResolver)
                        options.SerializerOptions.TypeInfoResolverChain.RemoveAt(i);
                }
            });
        }));
        using System.Net.Http.HttpClient client = application.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "scanner-test-key");
        foreach (bool ready in new[] { true, false })
        {
            manager.Ready = ready;
            using HttpResponseMessage health = await client.GetAsync("/health");
            await Assert.That(health.StatusCode).IsEqualTo(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable);
            using JsonDocument json = JsonDocument.Parse(await health.Content.ReadAsStringAsync());
            await Assert.That(json.RootElement.GetProperty("ready").GetBoolean()).IsEqualTo(ready);
        }
        using var scanContent = new ByteArrayContent([1]);
        using HttpResponseMessage scan = await client.PostAsync("/scan", scanContent);
        await Assert.That(scan.StatusCode).IsEqualTo(HttpStatusCode.OK);
        using JsonDocument verdict = JsonDocument.Parse(await scan.Content.ReadAsStringAsync());
        await Assert.That(verdict.RootElement.GetProperty("clean").GetBoolean()).IsTrue();
        await Assert.That(verdict.RootElement.GetProperty("threat").ValueKind).IsEqualTo(JsonValueKind.Null);

        using var queueContent = new ByteArrayContent([1]);
        using HttpResponseMessage queued = await client.PostAsync("/scan/jobs", queueContent);
        await Assert.That(queued.StatusCode).IsEqualTo(HttpStatusCode.Accepted);
        using JsonDocument accepted = JsonDocument.Parse(await queued.Content.ReadAsStringAsync());
        await Assert.That(accepted.RootElement.GetProperty("statusUrl").GetString()).IsEqualTo(queued.Headers.Location!.ToString());
        using HttpResponseMessage job = await client.GetAsync(queued.Headers.Location);
        await Assert.That(job.StatusCode).IsEqualTo(HttpStatusCode.OK);
        using JsonDocument record = JsonDocument.Parse(await job.Content.ReadAsStringAsync());
        await Assert.That(record.RootElement.GetProperty("id").GetString()).IsEqualTo(manager.Job.Id);
        await Assert.That(record.RootElement.GetProperty("result").ValueKind).IsEqualTo(JsonValueKind.Null);
    }

    private sealed class FakeScannerManager : IScannerManager
    {
        public bool Ready { get; set; }
        public VirusScanJobResponse Job { get; } = new(Guid.NewGuid().ToString("D"), "queued", null, null, DateTimeOffset.UtcNow, null);

        public ValueTask<string> GetVersion(CancellationToken cancellationToken = default) => new(Ready ? "ClamAV" : "");
        public ValueTask<VirusScanJobResponse?> GetJob(string jobId, CancellationToken cancellationToken = default) => new(Job);
        public ValueTask<VirusScanResponse> Scan(string temporaryPath, CancellationToken cancellationToken = default)
        {
            System.IO.File.Delete(temporaryPath);
            return new(new VirusScanResponse(true, null, "ClamAV"));
        }
        public ValueTask<VirusScanJobResponse> Queue(string temporaryPath, CancellationToken cancellationToken = default)
        {
            System.IO.File.Delete(temporaryPath);
            return new(Job);
        }
    }
}

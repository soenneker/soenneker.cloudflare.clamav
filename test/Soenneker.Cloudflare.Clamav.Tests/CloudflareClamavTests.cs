using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Services;
namespace Soenneker.Cloudflare.Clamav.Tests;

public sealed class CloudflareClamavTests
{
    [Test]
    public async Task Scan_requires_authentication(CancellationToken token)
    {
        await using var factory = new ScannerApplicationFactory();
        using HttpClient client = factory.CreateClient();
        using var content = new ByteArrayContent([1]);
        using HttpResponseMessage response = await client.PostAsync("/scan", content, token);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Oversized_upload_is_rejected_before_readiness(CancellationToken token)
    {
        await using var factory = new ScannerApplicationFactory();
        using HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ScannerApplicationFactory.ApiKey);
        using var content = new ByteArrayContent(new byte[17]);
        using HttpResponseMessage response = await client.PostAsync("/scan", content, token);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.RequestEntityTooLarge);
    }

    [Test]
    public async Task Readiness_fails_closed_while_liveness_remains_healthy(CancellationToken token)
    {
        await using var factory = new ScannerApplicationFactory();
        using HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ScannerApplicationFactory.ApiKey);
        using HttpResponseMessage ready = await client.GetAsync("/ready", token);
        using HttpResponseMessage health = await client.GetAsync("/health", token);
        await Assert.That(ready.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(health.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(ready.Headers.CacheControl!.NoStore).IsTrue();
    }

    [Test]
    public async Task Admission_rejects_excess_work_without_waiting_and_recovers_after_release()
    {
        await using var factory = new ScannerApplicationFactory();
        ScanAdmission admission = factory.Resolve<ScanAdmission>();
        await Assert.That(admission.TryAcquire()).IsTrue();
        await Assert.That(admission.TryAcquire()).IsTrue();
        await Assert.That(admission.TryAcquire()).IsFalse();
        admission.Release();
        await Assert.That(admission.TryAcquire()).IsTrue();
        admission.Release(); admission.Release();
    }

    [Test]
    public async Task Unready_scan_releases_its_admission_reservation(CancellationToken token)
    {
        await using var factory = new ScannerApplicationFactory();
        using HttpClient client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ScannerApplicationFactory.ApiKey);
        for (int i = 0; i < 4; i++)
        {
            using var content = new ByteArrayContent([1]);
            using HttpResponseMessage response = await client.PostAsync("/scan", content, token);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        }
    }
}

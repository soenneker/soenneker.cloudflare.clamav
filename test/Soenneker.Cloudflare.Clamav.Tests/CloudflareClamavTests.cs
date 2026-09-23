using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Verifies HTTP request validation through the scanner's real controller and dependency registrations.</summary>
public sealed class CloudflareClamavTests
{
    [Test]
    [Arguments("/scan")]
    [Arguments("/scan/jobs")]
    public async Task Scan_requires_authentication(string path)
    {
        await using var application = new ScannerApplicationFactory();
        using var client = application.CreateClient();
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
        using var client = application.CreateClient();
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
        using var client = application.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "scanner-test-key");
        using HttpResponseMessage response = await client.GetAsync("/scan/jobs/not-a-guid");
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }
}

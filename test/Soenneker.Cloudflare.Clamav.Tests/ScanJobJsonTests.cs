using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Utils.Json;

namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Verifies that JsonUtil preserves persisted job states and their camel-case field names.</summary>
public sealed class ScanJobJsonTests
{
    /// <summary>Round-trips pending and completed jobs, including nullable result fields and UTC timestamps.</summary>
    /// <param name="completed">Whether to include a completed clean verdict.</param>
    /// <returns>A task that completes after verifying the persisted representation.</returns>
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Job_round_trips_with_JsonUtil(bool completed)
    {
        var createdAt = new DateTimeOffset(2026, 9, 23, 0, 0, 0, TimeSpan.Zero);
        var job = new VirusScanJobResponse(Guid.NewGuid().ToString(), completed ? "completed" : "queued",
            completed ? new VirusScanResponse(true, null, "ClamAV") : null, null,
            createdAt, completed ? createdAt.AddMinutes(1) : null);

        byte[] json = JsonUtil.SerializeToUtf8Bytes(job);
        await Assert.That(Encoding.UTF8.GetString(json)).Contains("\"createdAt\"");
        await using var stream = new MemoryStream(json);
        VirusScanJobResponse? restored = await JsonUtil.Deserialize<VirusScanJobResponse>(stream, cancellationToken: default);
        await Assert.That(restored).IsEqualTo(job);
    }
}

using System.Threading.Tasks;
using System;
using Soenneker.Cloudflare.Clamav.Services;
using Soenneker.Cloudflare.Clamav.Responses;
namespace Soenneker.Cloudflare.Clamav.Tests;

public sealed class ClamdProtocolTests
{
    [Test]
    [Arguments("ClamAV 1.4.6/28168/Thu Oct 29 06:24:16 2026", true)]
    [Arguments("ClamAV 1.4.6/28168/Sun Oct 25 06:24:16 2026", false)]
    [Arguments("ClamAV 1.4.6/28168/Fri Oct 30 06:24:16 2026", false)]
    [Arguments("ClamAV 1.4.6", false)]
    [Arguments("ClamAV 1.4.6/bad/Thu Oct 29 06:24:16 2026", false)]
    public async Task Readiness_requires_fresh_parseable_loaded_signatures(string version, bool ready)
    {
        var now = new DateTimeOffset(2026, 10, 30, 3, 0, 0, TimeSpan.Zero);
        HealthResponse result = ClamdProtocol.ParseVersion(version, now, TimeSpan.FromDays(3), null);
        await Assert.That(result.Ready).IsEqualTo(ready);
    }

    [Test]
    [Arguments("stream: OK", "clean", true)]
    [Arguments("stream: Win.Test.EICAR_HDB-1 FOUND", "infected", false)]
    [Arguments("stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND", "inconclusive", false)]
    [Arguments("stream: Heuristics.Encrypted.Zip FOUND", "inconclusive", false)]
    [Arguments("stream: Heuristics.Broken.Executable FOUND", "inconclusive", false)]
    [Arguments("stream: Permission denied ERROR", "error", false)]
    [Arguments("", "error", false)]
    [Arguments("OK", "error", false)]
    [Arguments("stream: OK\nstream: bad FOUND", "error", false)]
    public async Task Ambiguous_or_incomplete_responses_are_never_clean(string response, string verdict, bool clean)
    {
        VirusScanResponse result = ClamdProtocol.Parse(response);
        await Assert.That(result.Verdict).IsEqualTo(verdict);
        await Assert.That(result.Clean).IsEqualTo(clean);
    }
}

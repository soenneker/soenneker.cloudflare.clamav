using System;
using Soenneker.Cloudflare.Clamav.Enums;
namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>A scan verdict bound to the uploaded bytes and the loaded signature database.</summary>
public sealed record VirusScanResponse(bool Clean, string? Threat, string Engine)
{
    public string Verdict { get; init; } = Clean ? ScanVerdict.Clean.Value : ScanVerdict.Infected.Value;
    public string Reason { get; init; } = Clean ? ScanReason.NoThreatDetected.Value : ScanReason.ThreatDetected.Value;
    public string ScanId { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public long Size { get; init; }
    public string EngineVersion { get; init; } = "";
    public string SignatureVersion { get; init; } = "";
    public DateTimeOffset? SignatureDate { get; init; }
    public double DurationMilliseconds { get; init; }
}

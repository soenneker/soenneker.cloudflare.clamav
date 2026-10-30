using Soenneker.Gen.EnumValues;
namespace Soenneker.Cloudflare.Clamav.Enums;

/// <summary>Stable machine-readable reasons for scan outcomes.</summary>
[EnumValue<string>]
public sealed partial class ScanReason
{
    public static readonly ScanReason NoThreatDetected = new("no_threat_detected");
    public static readonly ScanReason ThreatDetected = new("threat_detected");
    public static readonly ScanReason InspectionLimit = new("inspection_limit");
    public static readonly ScanReason Encrypted = new("encrypted");
    public static readonly ScanReason Unsupported = new("unsupported_or_malformed");
    public static readonly ScanReason EngineError = new("engine_error");
    public static readonly ScanReason Timeout = new("scan_timeout");
}

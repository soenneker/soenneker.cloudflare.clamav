using Soenneker.Gen.EnumValues;

namespace Soenneker.Cloudflare.Clamav.Enums;

/// <summary>
/// Defines the string values persisted and returned for background scan states.
/// </summary>
[EnumValue<string>]
public sealed partial class VirusScanJobStatus
{
    /// <summary>The job was created and is awaiting processing.</summary>
    public static readonly VirusScanJobStatus Queued = new("queued");
    /// <summary>The pipeline has started processing the uploaded file.</summary>
    public static readonly VirusScanJobStatus Processing = new("processing");
    /// <summary>The scan finished with a verdict, which may report either a clean file or a threat.</summary>
    public static readonly VirusScanJobStatus Completed = new("completed");
    /// <summary>The job could not be queued or completed, including cancellation during processing.</summary>
    public static readonly VirusScanJobStatus Failed = new("failed");
}

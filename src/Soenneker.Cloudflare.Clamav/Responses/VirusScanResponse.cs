namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>
/// Contains the verdict returned by a completed malware scan.
/// </summary>
/// <param name="Clean">Whether the scan reported the file as clean.</param>
/// <param name="Threat">The first detected signature, or <see langword="null"/> when no detection was returned.</param>
/// <param name="Engine">The scanning engine name, currently <c>ClamAV</c>.</param>
public sealed record VirusScanResponse(bool Clean, string? Threat, string Engine);

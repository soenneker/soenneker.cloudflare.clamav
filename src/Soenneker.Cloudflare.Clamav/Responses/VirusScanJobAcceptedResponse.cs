namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>
/// Identifies an accepted background scan and the endpoint used to poll its progress.
/// </summary>
/// <param name="Id">The job identifier in standard dashed GUID format.</param>
/// <param name="Status">The initial job status, <c>queued</c>.</param>
/// <param name="StatusUrl">An absolute status URL when available, otherwise a path relative to the service root.</param>
public sealed record VirusScanJobAcceptedResponse(string Id, string Status, string StatusUrl);

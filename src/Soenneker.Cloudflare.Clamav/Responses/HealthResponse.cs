namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>
/// Reports whether the ClamAV version query returned a nonempty result.
/// </summary>
/// <param name="Ready">Whether ClamAV reported a version. This does not verify R2 access or definition freshness.</param>
internal sealed record HealthResponse(bool Ready);

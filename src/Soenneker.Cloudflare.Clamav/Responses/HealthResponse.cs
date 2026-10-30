using System;
namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>Readiness of the daemon and its currently loaded signatures.</summary>
public sealed record HealthResponse(bool Ready, string? EngineVersion = null, string? SignatureVersion = null,
    DateTimeOffset? SignatureDate = null, DateTimeOffset? LastUpdateAt = null);

using System;

namespace Soenneker.Cloudflare.Clamav.Responses;

/// <summary>
/// Represents a persisted snapshot of a background scan's lifecycle and outcome.
/// </summary>
/// <param name="Id">The job identifier in standard dashed GUID format.</param>
/// <param name="Status">One of the serialized values defined by <see cref="Enums.VirusScanJobStatus"/>.</param>
/// <param name="Result">The scan verdict for a completed job, otherwise <see langword="null"/>.</param>
/// <param name="Error">A failure description for a failed job, otherwise <see langword="null"/>.</param>
/// <param name="CreatedAt">The UTC timestamp at which the job was created.</param>
/// <param name="CompletedAt">The UTC timestamp at which the job completed or failed, or <see langword="null"/> while pending.</param>
public sealed record VirusScanJobResponse(
    string Id,
    string Status,
    VirusScanResponse? Result,
    string? Error,
    DateTimeOffset CreatedAt,
    DateTimeOffset? CompletedAt);

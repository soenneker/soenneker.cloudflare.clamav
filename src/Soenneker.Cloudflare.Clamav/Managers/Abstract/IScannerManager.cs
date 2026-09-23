using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;

namespace Soenneker.Cloudflare.Clamav.Managers.Abstract;

/// <summary>
/// Queues and executes malware scans through the application's single scan pipeline.
/// </summary>
/// <remarks>
/// Work and uploaded files are held by the running process. Persisting a job record does not make
/// queued work durable across container restarts. Scan methods take ownership of their temporary file.
/// </remarks>
public interface IScannerManager
{
    /// <summary>
    /// Queues a scan and waits for its result.
    /// </summary>
    /// <param name="temporaryPath">Path to an uploaded file. The pipeline deletes it after processing or if enqueueing fails.</param>
    /// <param name="cancellationToken">Cancels enqueueing or waiting for the result; it does not cancel work already queued.</param>
    /// <returns>The scan verdict, including the first detected signature when a threat is found.</returns>
    /// <remarks>Scan failures are propagated to the caller. Work already queued may finish after the caller stops waiting.</remarks>
    ValueTask<VirusScanResponse> Scan(string temporaryPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Queues a scan for background processing and returns its persisted job state.
    /// </summary>
    /// <param name="temporaryPath">Path to an uploaded file. Ownership transfers to the pipeline, including cleanup on failure.</param>
    /// <param name="cancellationToken">Cancels initial persistence or enqueueing; background processing uses the queue's token.</param>
    /// <returns>The initial queued job record. Use <see cref="GetJob"/> to retrieve subsequent state changes.</returns>
    /// <remarks>The initial record is persisted before work is enqueued. A failed enqueue attempts to mark that record failed.</remarks>
    ValueTask<VirusScanJobResponse> Queue(string temporaryPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a persisted scan job, or null when it does not exist.
    /// </summary>
    /// <param name="jobId">The identifier returned when the job was queued.</param>
    /// <param name="cancellationToken">Cancels retrieval from the job store.</param>
    /// <returns>The most recently persisted job record, or <see langword="null"/> if it is absent.</returns>
    ValueTask<VirusScanJobResponse?> GetJob(string jobId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the bundled ClamAV version.
    /// </summary>
    /// <param name="cancellationToken">Cancels the version query.</param>
    /// <returns>The version text reported by ClamAV.</returns>
    ValueTask<string> GetVersion(CancellationToken cancellationToken = default);
}

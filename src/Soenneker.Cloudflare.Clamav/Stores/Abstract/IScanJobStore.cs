using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;

namespace Soenneker.Cloudflare.Clamav.Stores.Abstract;

/// <summary>
/// Persists and retrieves malware scan job states.
/// </summary>
/// <remarks>Stores job metadata and results, not uploaded file contents or executable queue entries.</remarks>
public interface IScanJobStore
{
    /// <summary>
    /// Saves a job state.
    /// </summary>
    /// <param name="job">The complete job record to create or replace, identified by its <see cref="VirusScanJobResponse.Id"/>.</param>
    /// <param name="cancellationToken">Cancels the persistence operation.</param>
    /// <returns>A task that completes when the record has been written.</returns>
    ValueTask Set(VirusScanJobResponse job, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a job state, or null when it does not exist.
    /// </summary>
    /// <param name="jobId">The identifier of the record to retrieve.</param>
    /// <param name="cancellationToken">Cancels the retrieval operation.</param>
    /// <returns>The persisted record, or <see langword="null"/> when it is absent.</returns>
    /// <remarks>Storage and deserialization failures propagate to the caller; they are not treated as missing records.</remarks>
    ValueTask<VirusScanJobResponse?> Get(string jobId, CancellationToken cancellationToken = default);
}

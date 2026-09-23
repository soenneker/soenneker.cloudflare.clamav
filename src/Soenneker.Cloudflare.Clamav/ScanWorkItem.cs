using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Managers;
using Soenneker.Cloudflare.Clamav.Responses;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>
/// Carries an owned temporary upload and its result destination through the in-process queue.
/// </summary>
/// <param name="Manager">The manager that processes the work item and cleans up its file.</param>
/// <param name="TemporaryPath">The temporary upload path owned by the pipeline.</param>
/// <param name="Job">The persisted job for an asynchronous request; <see langword="null"/> for a synchronous request.</param>
/// <param name="Completion">The synchronous caller's completion source; <see langword="null"/> for an asynchronous request.</param>
internal sealed record ScanWorkItem(
    ScannerManager Manager,
    string TemporaryPath,
    VirusScanJobResponse? Job,
    TaskCompletionSource<VirusScanResponse>? Completion);

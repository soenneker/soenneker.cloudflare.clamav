using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Enums;
using Soenneker.Cloudflare.Clamav.Managers.Abstract;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Stores.Abstract;
using Microsoft.Extensions.Logging;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Utils.BackgroundQueue.Abstract;
using Soenneker.Utils.File.Abstract;

namespace Soenneker.Cloudflare.Clamav.Managers;

public sealed class ScannerManager : IScannerManager
{
    private readonly IBackgroundQueue _backgroundQueue;
    private readonly IClamavUtil _clamav;
    private readonly IFileUtil _fileUtil;
    private readonly IScanJobStore _jobStore;
    private readonly ILogger<ScannerManager> _logger;

    public ScannerManager(IBackgroundQueue backgroundQueue, IClamavUtil clamav, IFileUtil fileUtil,
        IScanJobStore jobStore, ILogger<ScannerManager> logger)
    {
        _backgroundQueue = backgroundQueue;
        _clamav = clamav;
        _fileUtil = fileUtil;
        _jobStore = jobStore;
        _logger = logger;
    }

    public async ValueTask<VirusScanResponse> Scan(string temporaryPath, CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource<VirusScanResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var workItem = new ScanWorkItem(this, temporaryPath, null, completion);

        try
        {
            await _backgroundQueue.QueueValueTask(workItem, static (state, token) => state.Manager.Process(state, token),
                cancellationToken);
        }
        catch
        {
            await _fileUtil.TryDelete(temporaryPath, log: false, CancellationToken.None);
            throw;
        }

        return await completion.Task.WaitAsync(cancellationToken);
    }

    public async ValueTask<VirusScanJobResponse> Queue(string temporaryPath, CancellationToken cancellationToken = default)
    {
        var job = new VirusScanJobResponse(Guid.NewGuid().ToString(), VirusScanJobStatus.Queued.Value, null, null,
            DateTimeOffset.UtcNow, null);
        bool persisted = false;
        try
        {
            await _jobStore.Set(job, cancellationToken);
            persisted = true;
            var workItem = new ScanWorkItem(this, temporaryPath, job, null);
            await _backgroundQueue.QueueValueTask(workItem, static (state, token) => state.Manager.Process(state, token),
                cancellationToken);
        }
        catch
        {
            if (persisted)
            {
                VirusScanJobResponse failed = job with
                {
                    Status = VirusScanJobStatus.Failed.Value,
                    Error = "The scan could not be queued.",
                    CompletedAt = DateTimeOffset.UtcNow
                };

                try
                {
                    await _jobStore.Set(failed, CancellationToken.None);
                }
                catch (Exception persistenceException)
                {
                    _logger.LogError(persistenceException, "Could not persist failed virus scan job {JobId}", job.Id);
                }
            }

            await _fileUtil.TryDelete(temporaryPath, log: false, CancellationToken.None);
            throw;
        }

        return job;
    }

    public ValueTask<VirusScanJobResponse?> GetJob(string jobId, CancellationToken cancellationToken = default) =>
        _jobStore.Get(jobId, cancellationToken);

    public ValueTask<string> GetVersion(CancellationToken cancellationToken = default) =>
        _clamav.GetVersion(cancellationToken);

    private async ValueTask Process(ScanWorkItem workItem, CancellationToken cancellationToken)
    {
        try
        {
            VirusScanJobResponse? job = workItem.Job;
            if (job is not null)
            {
                job = job with {Status = VirusScanJobStatus.Processing.Value};
                try
                {
                    await _jobStore.Set(job, cancellationToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    _logger.LogWarning(exception, "Could not persist processing state for virus scan job {JobId}", job.Id);
                }
            }

            VirusScanResponse result = await ScanFile(workItem.TemporaryPath, cancellationToken);

            if (job is not null)
            {
                job = job with
                {
                    Status = VirusScanJobStatus.Completed.Value,
                    Result = result,
                    CompletedAt = DateTimeOffset.UtcNow
                };
                await _jobStore.Set(job, cancellationToken);
            }

            workItem.Completion?.TrySetResult(result);
        }
        catch (OperationCanceledException exception)
        {
            await Fail(workItem, "The scan was cancelled.", exception);
        }
        catch (Exception exception)
        {
            await Fail(workItem, "The scan could not be completed.", exception);
        }
        finally
        {
            await _fileUtil.TryDelete(workItem.TemporaryPath, log: false, CancellationToken.None);
        }
    }

    private async ValueTask<VirusScanResponse> ScanFile(string path, CancellationToken cancellationToken)
    {
        ClamavScanResult result = await _clamav.ScanFile(path, new ClamavScanOptions
        {
            UpdateDefinitions = true,
            Timeout = TimeSpan.FromMinutes(10)
        }, cancellationToken);

        return new VirusScanResponse(result.IsClean, result.Detections.FirstOrDefault()?.Signature, "ClamAV");
    }

    private async ValueTask Fail(ScanWorkItem workItem, string message, Exception exception)
    {
        _logger.LogError(exception, "Virus scan failed");

        if (workItem.Job is not null)
        {
            VirusScanJobResponse failed = workItem.Job with
            {
                Status = VirusScanJobStatus.Failed.Value,
                Error = message,
                CompletedAt = DateTimeOffset.UtcNow
            };

            try
            {
                await _jobStore.Set(failed, CancellationToken.None);
            }
            catch (Exception persistenceException)
            {
                _logger.LogError(persistenceException, "Could not persist failed virus scan job {JobId}", failed.Id);
            }
        }

        workItem.Completion?.TrySetException(exception);
    }
}

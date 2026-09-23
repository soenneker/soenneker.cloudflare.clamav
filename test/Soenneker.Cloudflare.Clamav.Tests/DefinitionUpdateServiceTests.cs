using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Clamav.Util.Abstract;
using Soenneker.Clamav.Util.Options;
using Soenneker.Clamav.Util.Results;
using Soenneker.Cloudflare.Clamav.Services;

namespace Soenneker.Cloudflare.Clamav.Tests;

public sealed class DefinitionUpdateServiceTests
{
    [Test]
    public async Task Retries_failed_updates_and_cancels_inflight_update_on_shutdown()
    {
        var clamav = new FakeClamavUtil();
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Scanner:DefinitionUpdateInterval"] = "00:00:00.020"
        }).Build();
        using var service = new DefinitionUpdateService(clamav, configuration, NullLogger<DefinitionUpdateService>.Instance);
        await service.StartAsync(CancellationToken.None);
        try
        {
            await clamav.SecondUpdateStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(100);
            await Assert.That(clamav.Calls).IsEqualTo(2);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        }

        await Assert.That(clamav.UpdateToken.IsCancellationRequested).IsTrue();
        await Assert.That(service.ExecuteTask!.IsCompletedSuccessfully).IsTrue();
    }

    [Test]
    public async Task Shutdown_cancels_wait_without_starting_an_update()
    {
        var clamav = new FakeClamavUtil();
        using var service = new DefinitionUpdateService(clamav, new ConfigurationBuilder().Build(),
            NullLogger<DefinitionUpdateService>.Instance);
        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(clamav.Calls).IsEqualTo(0);
        await Assert.That(service.ExecuteTask!.IsCompletedSuccessfully).IsTrue();
    }

    private sealed class FakeClamavUtil : IClamavUtil
    {
        public int Calls;
        public CancellationToken UpdateToken;
        public TaskCompletionSource SecondUpdateStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<IReadOnlyList<string>> UpdateDefinitions(string? databaseDirectory = null,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref Calls) == 1)
                throw new InvalidOperationException("Simulated update failure");
            UpdateToken = cancellationToken;
            SecondUpdateStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return Array.Empty<string>();
        }

        public ValueTask<ClamavScanResult> Scan(string path, ClamavScanOptions? options = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<ClamavScanResult> ScanFile(string filePath, ClamavScanOptions? options = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<ClamavScanResult> ScanDirectory(string directoryPath, ClamavScanOptions? options = null,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<string> GetVersion(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}

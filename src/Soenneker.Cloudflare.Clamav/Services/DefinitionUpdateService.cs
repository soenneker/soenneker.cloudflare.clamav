using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Soenneker.Clamav.Util.Abstract;

namespace Soenneker.Cloudflare.Clamav.Services;

/// <summary>Periodically refreshes the signature database used by the scanner and its daemon.</summary>
public sealed class DefinitionUpdateService : BackgroundService
{
    private readonly IClamavUtil _clamav;
    private readonly ILogger<DefinitionUpdateService> _logger;
    private readonly TimeSpan _interval;

    /// <summary>Creates the updater using Scanner:DefinitionUpdateInterval, which defaults to one hour.</summary>
    public DefinitionUpdateService(IClamavUtil clamav, IConfiguration configuration, ILogger<DefinitionUpdateService> logger)
    {
        _clamav = clamav;
        _logger = logger;
        _interval = configuration.GetValue("Scanner:DefinitionUpdateInterval", TimeSpan.FromHours(1));
        if (_interval.TotalMilliseconds < 1 || _interval.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(configuration), "Scanner:DefinitionUpdateInterval must be positive and no greater than 49 days.");
    }

    /// <summary>Refreshes definitions after each interval until the host stops.</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_interval);
        try
        {
            // First-scan initialization remains responsible for the initial update.
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    _logger.LogInformation("Refreshing ClamAV definitions");
                    await _clamav.UpdateDefinitions(cancellationToken: stoppingToken);
                    // clamd's default SelfCheck detects database changes and reloads them.
                    _logger.LogInformation("ClamAV definitions refreshed; the daemon will load changes on its next database check");
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception)
                {
                    _logger.LogError(exception, "ClamAV definition refresh failed; retrying on the next timer tick (interval {Interval})", _interval);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown while waiting for the next update.
        }
    }
}

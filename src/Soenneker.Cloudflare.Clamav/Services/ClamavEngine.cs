using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Soenneker.Asyncs.Semaphores;
using System.Collections.Generic;
using Soenneker.Cloudflare.Clamav.Options;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Services.Abstract;

namespace Soenneker.Cloudflare.Clamav.Services;

public sealed class ClamavEngine(ScannerOptions options, ClamdProtocol protocol, ILogger<ClamavEngine> logger) : BackgroundService, IScanEngine
{
    private readonly AsyncSemaphore _scanSlots = new(options.MaximumConcurrentScans);
    private Process? _daemon;
    private DateTimeOffset? _lastUpdate;
    private volatile bool _ready;
    private string DatabaseDirectory => Path.Combine(options.WorkingDirectory, "database");
    private string RuntimeDirectory(string tool) => Path.Combine(AppContext.BaseDirectory, "Resources",
        OperatingSystem.IsWindows() ? "win-x64" : "linux-x64", tool);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.ApiKey.Length < 32)
            throw new InvalidOperationException("Scanner:ApiKey must contain at least 32 characters.");
        Directory.CreateDirectory(options.WorkingDirectory);
        Directory.CreateDirectory(DatabaseDirectory);
        foreach (string orphan in Directory.EnumerateFiles(options.WorkingDirectory, "*.scan", SearchOption.TopDirectoryOnly))
            File.Delete(orphan);
        // Seeds are copied once. Never overwrite newer local signatures or FreshClam cooldown state.
        string seed = Path.Combine(AppContext.BaseDirectory, "Resources", "clamav-database");
        if (Directory.Exists(seed))
            foreach (string path in Directory.EnumerateFiles(seed))
            {
                string target = Path.Combine(DatabaseDirectory, Path.GetFileName(path));
                if (!File.Exists(target)) File.Copy(path, target, false);
            }
        DateTimeOffset nextUpdate = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var leases = new List<SemaphoreLease>(options.MaximumConcurrentScans);
                try
                {
                    for (int i = 0; i < options.MaximumConcurrentScans; i++)
                        leases.Add(await _scanSlots.Acquire(stoppingToken));
                    if (DateTimeOffset.UtcNow >= nextUpdate)
                    {
                        try
                        {
                            // Drain scans before changing the database, then restart to confirm exactly what was loaded.
                            _ready = false;
                            await Refresh(stoppingToken);
                            _lastUpdate = DateTimeOffset.UtcNow;
                            StopDaemon();
                            nextUpdate = DateTimeOffset.UtcNow + options.DefinitionUpdateInterval;
                        }
                        catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                        {
                            ScanTelemetry.UpdateFailures.Add(1);
                            logger.LogError(exception, "Signature refresh failed; retaining the last usable database");
                            nextUpdate = DateTimeOffset.UtcNow.AddMinutes(5);
                        }
                    }
                    if (_daemon is null || _daemon.HasExited) await StartDaemon(stoppingToken);
                    HealthResponse health = await QueryHealth(stoppingToken);
                    _ready = health.Ready;
                    ScanTelemetry.SetHealth(health);
                }
                finally { foreach (SemaphoreLease lease in leases) lease.Dispose(); }
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                _ready = false;
                StopDaemon();
                logger.LogError(exception, "Scanner supervision failed; retrying in 30 seconds");
            }
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    public async ValueTask<HealthResponse> Health(CancellationToken cancellationToken)
    {
        if (!_ready) return new(false, LastUpdateAt: _lastUpdate);
        try
        {
            HealthResponse health = await QueryHealth(cancellationToken);
            ScanTelemetry.SetHealth(health);
            return health;
        }
        catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or FormatException or InvalidOperationException)
        {
            var health = new HealthResponse(false, LastUpdateAt: _lastUpdate);
            ScanTelemetry.SetHealth(health);
            return health;
        }
    }

    private async ValueTask<HealthResponse> QueryHealth(CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        if (_daemon is null || _daemon.HasExited || await protocol.Command(options.DaemonPort, "PING", timeout.Token) != "PONG")
            return new(false, LastUpdateAt: _lastUpdate);
        string version = await protocol.Command(options.DaemonPort, "VERSION", timeout.Token);
        return ClamdProtocol.ParseVersion(version, DateTimeOffset.UtcNow, options.MaximumDefinitionAge, _lastUpdate);
    }

    public async ValueTask<VirusScanResponse> Scan(string path, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ScanTimeout);
        using (await _scanSlots.Acquire(timeout.Token))
        {
            HealthResponse health = await Health(timeout.Token);
            if (!health.Ready) throw new InvalidOperationException("Scanner is not ready.");
            string response = await protocol.Scan(options.DaemonPort, path, timeout.Token);
            return ClamdProtocol.Parse(response) with
            {
                EngineVersion = health.EngineVersion!, SignatureVersion = health.SignatureVersion!, SignatureDate = health.SignatureDate
            };
        }
    }

    private async Task Refresh(CancellationToken token)
    {
        string config = Path.Combine(options.WorkingDirectory, "freshclam.conf");
        await File.WriteAllTextAsync(config,
            "DatabaseMirror database.clamav.net\nScriptedUpdates yes\nCompressLocalDatabase no\nChecks 24\n" +
            (OperatingSystem.IsLinux() ? $"DatabaseOwner {Environment.UserName}\n" : ""), token);
        ProcessStartInfo start = CreateStartInfo("freshclam", "bin", "freshclam");
        start.ArgumentList.Add($"--config-file={config}");
        start.ArgumentList.Add($"--datadir={DatabaseDirectory}");
        start.ArgumentList.Add("--stdout");
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        AttachOutput(process, "freshclam");
        process.Start();
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            if (process.ExitCode != 0) throw new IOException($"FreshClam exited with code {process.ExitCode}.");
        }
        finally
        {
            if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); }
        }
    }

    private async Task StartDaemon(CancellationToken token)
    {
        StopDaemon();
        string configPath = Path.Combine(options.WorkingDirectory, "clamd.conf");
        string config = $"TCPSocket {options.DaemonPort}\nTCPAddr 127.0.0.1\nForeground yes\n" +
            $"DatabaseDirectory {DatabaseDirectory}\nTemporaryDirectory {options.WorkingDirectory}\n" +
            $"MaxThreads {options.MaximumConcurrentScans}\nMaxQueue {options.MaximumConcurrentScans * 2}\n" +
            $"StreamMaxLength {options.MaximumFileSize}\nMaxFileSize {options.MaximumFileSize}\n" +
            $"MaxScanSize {options.MaximumExpandedSize}\nMaxFiles {options.MaximumArchiveFiles}\nMaxRecursion {options.MaximumRecursion}\n" +
            $"MaxScanTime {(long)options.ScanTimeout.TotalMilliseconds}\nReadTimeout 30\nCommandReadTimeout 5\n" +
            "AlertExceedsMax yes\nAlertEncrypted yes\nAlertBrokenExecutables yes\nAlertBrokenMedia yes\n" +
            "SelfCheck 0\nConcurrentDatabaseReload no\nLogTime yes\n";
        await File.WriteAllTextAsync(configPath, config, token);
        var daemon = new Process { StartInfo = CreateStartInfo("clamav", "sbin", "clamd") };
        daemon.StartInfo.ArgumentList.Add($"--config-file={configPath}");
        AttachOutput(daemon, "clamd");
        daemon.Start(); daemon.BeginOutputReadLine(); daemon.BeginErrorReadLine();
        _daemon = daemon;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(3));
        while (!daemon.HasExited)
        {
            try
            {
                if ((await QueryHealth(timeout.Token)).EngineVersion is not null) return;
            }
            catch (SocketException) { }
            await Task.Delay(500, timeout.Token);
        }
        throw new IOException($"ClamAV daemon exited with code {daemon.ExitCode}.");
    }

    private ProcessStartInfo CreateStartInfo(string tool, string directory, string executable)
    {
        string runtime = RuntimeDirectory(tool);
        string file = OperatingSystem.IsWindows() ? Path.Combine(runtime, executable + ".exe") : Path.Combine(runtime, directory, executable);
        var start = new ProcessStartInfo(file) { WorkingDirectory = options.WorkingDirectory, UseShellExecute = false,
            RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        start.Environment["TZ"] = "UTC";
        if (OperatingSystem.IsLinux())
        {
            start.Environment["LD_LIBRARY_PATH"] = Path.Combine(runtime, "lib64") + ":" + Path.Combine(runtime, "lib");
            start.Environment["CVD_CERTS_DIR"] = Path.Combine(runtime, "etc", "certs");
        }
        return start;
    }

    private void AttachOutput(Process process, string name)
    {
        process.OutputDataReceived += (_, args) => { if (args.Data is not null) logger.LogInformation("{Process}: {Output}", name, args.Data); };
        process.ErrorDataReceived += (_, args) => { if (args.Data is not null) logger.LogWarning("{Process}: {Output}", name, args.Data); };
    }

    private void StopDaemon()
    {
        _ready = false;
        if (_daemon is null) return;
        try { if (!_daemon.HasExited) _daemon.Kill(true); }
        catch (InvalidOperationException) { }
        _daemon.Dispose(); _daemon = null;
    }

    public override void Dispose() { StopDaemon(); base.Dispose(); }
}

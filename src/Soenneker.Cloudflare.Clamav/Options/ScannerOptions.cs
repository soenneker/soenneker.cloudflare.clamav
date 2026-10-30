using System;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace Soenneker.Cloudflare.Clamav.Options;

/// <summary>Validated resource limits shared by the HTTP host and scan engine.</summary>
public sealed class ScannerOptions
{
    public string ApiKey { get; set; } = "";
    public long MaximumFileSize { get; set; } = 100 * 1024 * 1024;
    public int MaximumConcurrentScans { get; set; } = 2;
    public long TemporaryByteBudget { get; set; } = 256 * 1024 * 1024;
    public TimeSpan UploadTimeout { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan ScanTimeout { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan DefinitionUpdateInterval { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan MaximumDefinitionAge { get; set; } = TimeSpan.FromDays(3);
    public long MaximumExpandedSize { get; set; } = 256 * 1024 * 1024;
    public int MaximumArchiveFiles { get; set; } = 10000;
    public int MaximumRecursion { get; set; } = 16;
    public int DaemonPort { get; set; } = 3310;
    public string WorkingDirectory { get; set; } = Path.Combine(Path.GetTempPath(), "clamav-scanner");

    public static ScannerOptions Read(IConfiguration configuration)
    {
        var options = new ScannerOptions();
        configuration.GetSection("Scanner").Bind(options);
        if (options.MaximumFileSize is < 1 or > 104857600 || options.MaximumConcurrentScans is < 1 or > 16 ||
            options.TemporaryByteBudget < options.MaximumFileSize || options.MaximumExpandedSize < options.MaximumFileSize ||
            options.MaximumExpandedSize > 1073741824 || options.MaximumArchiveFiles is < 1 or > 100000 ||
            options.MaximumRecursion is < 1 or > 64 || options.DaemonPort is < 1024 or > 65535 ||
            options.UploadTimeout < TimeSpan.FromSeconds(1) || options.UploadTimeout > TimeSpan.FromMinutes(5) ||
            options.ScanTimeout < TimeSpan.FromSeconds(1) || options.ScanTimeout > TimeSpan.FromMinutes(10) ||
            options.DefinitionUpdateInterval < TimeSpan.FromMinutes(5) || options.DefinitionUpdateInterval > TimeSpan.FromDays(1) ||
            options.MaximumDefinitionAge < TimeSpan.FromHours(1) || options.MaximumDefinitionAge > TimeSpan.FromDays(7))
            throw new InvalidOperationException("Invalid Scanner limits. Check upload, concurrency, archive, timeout, and definition settings.");
        return options;
    }
}

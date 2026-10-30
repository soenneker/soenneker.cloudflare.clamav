using System.Diagnostics;
using System;
using System.Threading;
using Soenneker.Cloudflare.Clamav.Responses;
using System.Diagnostics.Metrics;
namespace Soenneker.Cloudflare.Clamav.Services;

/// <summary>OpenTelemetry-compatible instruments for scanner resource use and outcomes.</summary>
public static class ScanTelemetry
{
    private static long _signatureTimestamp;
    private static int _ready;
    public static void SetHealth(HealthResponse health)
    {
        Volatile.Write(ref _ready, health.Ready ? 1 : 0);
        Interlocked.Exchange(ref _signatureTimestamp, health.SignatureDate?.ToUnixTimeSeconds() ?? 0);
    }
    public static readonly Meter Meter = new("Soenneker.Cloudflare.Clamav", "1.0.0");
    public static readonly ObservableGauge<int> Ready = Meter.CreateObservableGauge("scanner.ready", () => Volatile.Read(ref _ready));
    public static readonly ObservableGauge<long> SignatureAge = Meter.CreateObservableGauge("scanner.signature.age", () =>
        Interlocked.Read(ref _signatureTimestamp) is > 0 and var timestamp ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp : -1, "s");
    public static readonly ActivitySource Activities = new("Soenneker.Cloudflare.Clamav");
    public static readonly Counter<long> Completed = Meter.CreateCounter<long>("scanner.scans");
    public static readonly Counter<long> Rejected = Meter.CreateCounter<long>("scanner.rejected");
    public static readonly Counter<long> UpdateFailures = Meter.CreateCounter<long>("scanner.definition_update_failures");
    public static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("scanner.scan.duration", "ms");
    public static readonly UpDownCounter<long> ReservedBytes = Meter.CreateUpDownCounter<long>("scanner.temporary.reserved", "By");
    public static readonly UpDownCounter<long> Active = Meter.CreateUpDownCounter<long>("scanner.active");
}

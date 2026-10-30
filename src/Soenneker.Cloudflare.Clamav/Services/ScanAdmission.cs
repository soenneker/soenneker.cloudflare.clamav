using System;
using Soenneker.Cloudflare.Clamav.Options;
namespace Soenneker.Cloudflare.Clamav.Services;

/// <summary>Reserves an entire upload allowance before reading bytes, without an unbounded waiting queue.</summary>
public sealed class ScanAdmission(ScannerOptions options)
{
    private readonly object _gate = new();
    private int _active;
    private long _reserved;

    public bool TryAcquire()
    {
        lock (_gate)
        {
            if (_active >= options.MaximumConcurrentScans || options.MaximumFileSize > options.TemporaryByteBudget - _reserved)
            {
                ScanTelemetry.Rejected.Add(1);
                return false;
            }
            _active++;
            _reserved += options.MaximumFileSize;
            ScanTelemetry.Active.Add(1);
            ScanTelemetry.ReservedBytes.Add(options.MaximumFileSize);
            return true;
        }
    }

    public void Release()
    {
        lock (_gate)
        {
            if (_active == 0) throw new InvalidOperationException("No active scan reservation.");
            _active--;
            _reserved -= options.MaximumFileSize;
            ScanTelemetry.Active.Add(-1);
            ScanTelemetry.ReservedBytes.Add(-options.MaximumFileSize);
        }
    }
}

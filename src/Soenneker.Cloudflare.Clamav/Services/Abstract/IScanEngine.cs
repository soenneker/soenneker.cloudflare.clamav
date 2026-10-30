using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;
namespace Soenneker.Cloudflare.Clamav.Services.Abstract;

/// <summary>Scans bounded uploads using a supervised daemon with fresh signatures.</summary>
public interface IScanEngine
{
    /// <summary>Queries the live daemon and checks the loaded database age.</summary>
    ValueTask<HealthResponse> Health(CancellationToken cancellationToken);
    /// <summary>Inspects one file. Errors and incomplete inspections never produce a clean verdict.</summary>
    ValueTask<VirusScanResponse> Scan(string path, CancellationToken cancellationToken);
}

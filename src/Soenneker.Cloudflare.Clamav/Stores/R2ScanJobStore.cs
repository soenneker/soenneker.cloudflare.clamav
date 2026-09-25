using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Stores.Abstract;
using Soenneker.Librarian.Abstractions;
using Soenneker.Librarian.Abstractions.Transactions;
using Soenneker.Utils.Json;

namespace Soenneker.Cloudflare.Clamav.Stores;

public sealed class R2ScanJobStore : IScanJobStore
{
    private const string ContainerName = "scan-jobs";

    private readonly ILibrarianDatabase _database;

    public R2ScanJobStore(ILibrarianDatabase database)
    {
        _database = database;
    }

    public async ValueTask Set(VirusScanJobResponse job, CancellationToken cancellationToken = default)
    {
        string json = JsonUtil.Serialize(job, LibraryJsonContext.Get<VirusScanJobResponse>());
        var batch = new LibrarianBatch([new LibrarianWrite(ContainerName, job.Id, json)]);

        // R2 batches persist the snapshot before publishing the new in-memory state.
        if (!await _database.Execute(batch, cancellationToken))
            throw new InvalidOperationException($"Scan job '{job.Id}' could not be persisted.");
    }

    public async ValueTask<VirusScanJobResponse?> Get(string jobId, CancellationToken cancellationToken = default)
    {
        ILibrarianContainer container = await _database.GetContainer(ContainerName, cancellationToken);
        string? json = await container.GetItem(jobId, cancellationToken);
        if (json is null)
            return null;

        return JsonUtil.Deserialize(json, LibraryJsonContext.Get<VirusScanJobResponse>())
            ?? throw new InvalidDataException($"Scan job '{jobId}' did not contain a valid job record.");
    }
}

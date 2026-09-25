using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Stores;
using Soenneker.Librarian.Core;

namespace Soenneker.Cloudflare.Clamav.Tests;

public sealed class R2ScanJobStoreTests
{
    [Test]
    public async Task Set_persists_jobs_and_updates_before_returning()
    {
        await using var database = new TestSnapshotDatabase();
        var store = new R2ScanJobStore(database);
        var job = new VirusScanJobResponse(Guid.NewGuid().ToString("D"), "queued", null, null, DateTimeOffset.UtcNow, null);
        await Assert.That(await store.Get(job.Id)).IsNull();
        await store.Set(job);
        await Assert.That(database.Writes).IsEqualTo(1);

        VirusScanJobResponse completed = job with
        {
            Status = "completed", Result = new VirusScanResponse(true, null, "ClamAV"), CompletedAt = DateTimeOffset.UtcNow
        };
        await store.Set(completed);
        await Assert.That(database.Writes).IsEqualTo(2);

        await using var reloaded = new TestSnapshotDatabase { Snapshot = database.Snapshot };
        await Assert.That(await new R2ScanJobStore(reloaded).Get(job.Id)).IsEqualTo(completed);
    }

    [Test]
    public async Task Failed_snapshot_write_does_not_publish_new_job_state()
    {
        await using var database = new TestSnapshotDatabase();
        var store = new R2ScanJobStore(database);
        var job = new VirusScanJobResponse(Guid.NewGuid().ToString("D"), "queued", null, null, DateTimeOffset.UtcNow, null);
        await store.Set(job);
        string? persisted = database.Snapshot;
        database.FailWrites = true;
        bool failed = false;
        try
        {
            await store.Set(job with { Status = "processing" });
        }
        catch (IOException)
        {
            failed = true;
        }
        finally
        {
            database.FailWrites = false;
        }
        await Assert.That(failed).IsTrue();
        await Assert.That(database.Snapshot).IsEqualTo(persisted);
        await Assert.That(await store.Get(job.Id)).IsEqualTo(job);
    }

    private sealed class TestSnapshotDatabase() : SnapshotLibrarianDatabase(NullLogger.Instance)
    {
        public string? Snapshot { get; set; }
        public int Writes { get; private set; }
        public bool FailWrites { get; set; }

        protected override ValueTask<string?> ReadSnapshot(CancellationToken cancellationToken) => new(Snapshot);

        protected override ValueTask WriteSnapshot(string json, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailWrites)
                throw new IOException("Simulated snapshot upload failure.");
            Snapshot = json;
            Writes++;
            return ValueTask.CompletedTask;
        }
    }
}

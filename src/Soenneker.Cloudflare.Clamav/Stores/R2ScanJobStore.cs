using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Stores.Abstract;
using Microsoft.Extensions.Configuration;
using Microsoft.Kiota.Abstractions;
using Soenneker.Cloudflare.R2.Abstract;
using Soenneker.Utils.Json;

namespace Soenneker.Cloudflare.Clamav.Stores;

public sealed class R2ScanJobStore : IScanJobStore
{
    private readonly ICloudflareR2Util _r2;
    private readonly string _accountId;
    private readonly string _apiKey;
    private readonly string _bucket;

    public R2ScanJobStore(ICloudflareR2Util r2, IConfiguration configuration)
    {
        _r2 = r2;
        _accountId = Require(configuration, "Cloudflare:AccountId");
        _apiKey = Require(configuration, "Cloudflare:ApiKey");
        _bucket = Require(configuration, "Scanner:R2:Bucket");
    }

    public async ValueTask Set(VirusScanJobResponse job, CancellationToken cancellationToken = default)
    {
        byte[] json = JsonUtil.SerializeToUtf8Bytes(job);
        await using var stream = new MemoryStream(json, writable: false);
        await _r2.PutObject(_accountId, _bucket, GetKey(job.Id), stream, "application/json", _apiKey, cancellationToken);
    }

    public async ValueTask<VirusScanJobResponse?> Get(string jobId, CancellationToken cancellationToken = default)
    {
        try
        {
            await using Stream? stream = await _r2.GetObject(_accountId, _bucket, GetKey(jobId), _apiKey, cancellationToken);
            if (stream is null)
                return null;

            return await JsonUtil.Deserialize<VirusScanJobResponse>(stream, cancellationToken: cancellationToken)
                ?? throw new InvalidDataException($"Scan job '{jobId}' did not contain a valid job record.");
        }
        catch (ApiException exception) when (exception.ResponseStatusCode == 404)
        {
            return null;
        }
    }

    private static string GetKey(string jobId) => $"scanner/jobs/{jobId}.json";

    private static string Require(IConfiguration configuration, string key) =>
        configuration[key] is {Length: > 0} value
            ? value
            : throw new InvalidOperationException($"{key} is not configured.");
}

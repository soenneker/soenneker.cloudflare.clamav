using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Soenneker.Cloudflare.Clamav.Options;
using Soenneker.Cloudflare.Clamav.Responses;
using Soenneker.Cloudflare.Clamav.Services;
using Soenneker.Cloudflare.Clamav.Services.Abstract;
namespace Soenneker.Cloudflare.Clamav.Endpoints;

/// <summary>Exposes liveness, authenticated readiness, and bounded synchronous scanning.</summary>
public sealed class ScannerEndpoints(ScannerOptions options, IScanEngine engine, ScanAdmission admission, ILogger<ScannerEndpoints> logger)
{
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health", () => TypedResults.Ok(new HealthResponse(true)))
            .WithName("Health").WithSummary("Checks HTTP host liveness.");
        endpoints.MapGet("/ready", (ScannerEndpoints handler, HttpContext context) => handler.Ready(context))
            .WithName("Ready").WithSummary("Checks the daemon and loaded signature freshness.").Produces<HealthResponse>().Produces<HealthResponse>(503).ProducesProblem(401);
        endpoints.MapPost("/scan", (ScannerEndpoints handler, HttpContext context) => handler.Scan(context))
            .WithName(nameof(Scan)).WithSummary("Inspects raw file bytes under bounded resource limits.")
            .Produces<VirusScanResponse>().ProducesProblem(401).ProducesProblem(408).ProducesProblem(413).ProducesProblem(429).ProducesProblem(503);
        // Contract metadata for the public Worker. Durable jobs are deliberately not accepted by a standalone container.
        endpoints.MapPost("/scan/jobs", () => TypedResults.Problem(statusCode: 501, title: "Use the Cloudflare Worker for durable jobs."))
            .WithName("Queue").WithSummary("Accepts a durable scan through the Worker; requires Idempotency-Key.")
            .Produces<VirusScanJobAcceptedResponse>(202).ProducesProblem(400).ProducesProblem(401).ProducesProblem(409).ProducesProblem(413).ProducesProblem(429).ProducesProblem(501);
        endpoints.MapGet("/scan/jobs/{jobId}", (string jobId) => TypedResults.Problem(statusCode: 501, title: "Use the Cloudflare Worker for durable jobs."))
            .WithName("GetJob").WithSummary("Retrieves durable job state through the Worker.")
            .Produces<VirusScanJobResponse>().ProducesProblem(401).ProducesProblem(404).ProducesProblem(501);
    }

    private bool Authorized(HttpContext context)
    {
        string supplied = context.Request.Headers.Authorization.ToString();
        return options.ApiKey.Length >= 32 && CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(supplied)), SHA256.HashData(Encoding.UTF8.GetBytes("Bearer " + options.ApiKey)));
    }

    public async Task<IResult> Ready(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!Authorized(context)) return TypedResults.Problem(statusCode: 401);
        HealthResponse health = await engine.Health(context.RequestAborted);
        return TypedResults.Json(health, Soenneker.Cloudflare.Clamav.Stores.LibraryJsonContext.Default.HealthResponse, statusCode: health.Ready ? 200 : 503);
    }

    public async Task<IResult> Scan(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!Authorized(context)) return TypedResults.Problem(statusCode: 401);
        if (context.Request.ContentLength > options.MaximumFileSize) return TypedResults.Problem(statusCode: 413, title: "Upload exceeds the scan limit.");
        if (!admission.TryAcquire())
        {
            context.Response.Headers.RetryAfter = "5";
            return TypedResults.Problem(statusCode: 429, title: "Scanner capacity is reserved. Retry later.");
        }
        string scanId = Guid.NewGuid().ToString();
        string? path = null;
        using Activity? activity = ScanTelemetry.Activities.StartActivity("scan");
        long started = Stopwatch.GetTimestamp();
        try
        {
            if (!(await engine.Health(context.RequestAborted)).Ready)
                return TypedResults.Problem(statusCode: 503, title: "Scanner is warming up or signatures are stale.");
            Directory.CreateDirectory(options.WorkingDirectory);
            path = Path.Combine(options.WorkingDirectory, scanId + ".scan");
            using var uploadTimeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            uploadTimeout.CancelAfter(options.UploadTimeout);
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long size = 0;
            await using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous))
            {
                byte[] buffer = new byte[65536];
                int read;
                while ((read = await context.Request.Body.ReadAsync(buffer, uploadTimeout.Token)) > 0)
                {
                    size += read;
                    if (size > options.MaximumFileSize) return TypedResults.Problem(statusCode: 413, title: "Upload exceeds the scan limit.");
                    hash.AppendData(buffer, 0, read);
                    await file.WriteAsync(buffer.AsMemory(0, read), uploadTimeout.Token);
                }
            }
            VirusScanResponse result = await engine.Scan(path, context.RequestAborted);
            result = result with { ScanId = scanId, Sha256 = Convert.ToHexStringLower(hash.GetHashAndReset()), Size = size,
                DurationMilliseconds = Stopwatch.GetElapsedTime(started).TotalMilliseconds };
            ScanTelemetry.Completed.Add(1, new System.Collections.Generic.KeyValuePair<string, object?>("verdict", result.Verdict));
            logger.LogInformation("Scan {ScanId} completed: {Verdict}, {Reason}, {Bytes} bytes, {DurationMs} ms, signatures {Signatures}",
                scanId, result.Verdict, result.Reason, size, result.DurationMilliseconds, result.SignatureVersion);
            return TypedResults.Ok(result);
        }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
        {
            return TypedResults.Problem(statusCode: 408, title: "Upload or scan deadline exceeded.");
        }
        catch (BadHttpRequestException exception) when (exception.StatusCode == 413)
        {
            return TypedResults.Problem(statusCode: 413, title: "Upload exceeds the scan limit.");
        }
        catch (Exception exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            logger.LogError(exception, "Scan {ScanId} failed", scanId);
            return TypedResults.Problem(statusCode: 503, title: "The scan could not be completed.");
        }
        finally
        {
            try { if (path is not null) File.Delete(path); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            { logger.LogError(exception, "Could not remove scan upload {ScanId}", scanId); }
            finally { admission.Release(); }
            ScanTelemetry.Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
    }
}

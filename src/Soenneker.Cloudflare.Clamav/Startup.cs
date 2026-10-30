using Microsoft.AspNetCore.Builder;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using OpenTelemetry.Resources;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Soenneker.Cloudflare.Clamav.Endpoints;
using Soenneker.Cloudflare.Clamav.OpenApi;
using Soenneker.Cloudflare.Clamav.Options;
using Soenneker.Cloudflare.Clamav.Services;
using Soenneker.Cloudflare.Clamav.Services.Abstract;
using Soenneker.Cloudflare.Clamav.Stores;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>Configures the scanner container. The Worker owns durable job storage and delivery.</summary>
public sealed class Startup(IConfiguration configuration)
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton(_ => ScannerOptions.Read(configuration));
        services.AddOptions<KestrelServerOptions>().Configure<ScannerOptions>((server, scanner) =>
        {
            server.Limits.MaxRequestBodySize = scanner.MaximumFileSize;
            server.Limits.MaxConcurrentConnections = 64;
            server.AddServerHeader = false;
        });
        services.AddSingleton<ClamdProtocol>();
        services.AddSingleton<ScanAdmission>();
        services.AddSingleton<ClamavEngine>();
        services.AddSingleton<IScanEngine>(provider => provider.GetRequiredService<ClamavEngine>());
        if (System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name != "GetDocument.Insider")
            services.AddHostedService(provider => provider.GetRequiredService<ClamavEngine>());
        services.AddScoped<ScannerEndpoints>();
        services.ConfigureHttpJsonOptions(options => options.SerializerOptions.TypeInfoResolverChain.Insert(0, LibraryJsonContext.Default));
        services.AddOpenApi("v1", ScannerOpenApi.Configure);
        if (!string.IsNullOrWhiteSpace(configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
            services.AddOpenTelemetry()
                .ConfigureResource(resource => resource.AddService("Soenneker.Cloudflare.Clamav"))
                .WithMetrics(metrics => metrics.AddMeter("Soenneker.Cloudflare.Clamav").AddAspNetCoreInstrumentation().AddOtlpExporter())
                .WithTracing(tracing => tracing.AddSource("Soenneker.Cloudflare.Clamav").AddAspNetCoreInstrumentation().AddOtlpExporter());
    }

    public void Configure(WebApplication app, IWebHostEnvironment environment)
    {
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            await next(context);
        });
        ScannerEndpoints.Map(app);
    }
}

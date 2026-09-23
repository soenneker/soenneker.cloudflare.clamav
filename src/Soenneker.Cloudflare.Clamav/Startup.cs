using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Soenneker.Clamav.Util.Registrars;
using Soenneker.Cloudflare.R2.Registrars;
using Soenneker.Utils.BackgroundQueue.Registrars;
using Soenneker.Cloudflare.Clamav.Managers;
using Soenneker.Cloudflare.Clamav.Managers.Abstract;
using Soenneker.Cloudflare.Clamav.Stores;
using Soenneker.Cloudflare.Clamav.Stores.Abstract;
using Soenneker.Cloudflare.Clamav.OpenApi;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>
/// Configures the application services and request pipeline.
/// </summary>
public sealed class Startup
{
    private const long DefaultMaximumFileSize = 100 * 1024 * 1024;

    private readonly IConfiguration _configuration;

    /// <summary>Initializes service startup with the host's configuration sources.</summary>
    /// <param name="configuration">Configuration containing scanner limits and dependency settings.</param>
    public Startup(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    /// <summary>Registers controllers, the ClamAV daemon utility, the background queue, and the R2 job store.</summary>
    /// <param name="services">The host's service collection.</param>
    /// <remarks>Also configures Kestrel's request body limit, defaulting to 100 MiB.</remarks>
    public void ConfigureServices(IServiceCollection services)
    {
        long maximumFileSize = _configuration.GetValue("Scanner:MaximumFileSize", DefaultMaximumFileSize);

        services.Configure<KestrelServerOptions>(options => options.Limits.MaxRequestBodySize = maximumFileSize);
        services.AddClamavUtilAsSingleton(options =>
        {
            options.UseDaemon = true;
        });
        services.AddCloudflareR2UtilAsSingleton();
        services.AddBackgroundQueueAsSingleton();
        services.AddSingleton<IScanJobStore, R2ScanJobStore>();
        services.AddSingleton<IScannerManager, ScannerManager>();
        services.AddControllers();
        services.AddOpenApi("v1", options => ScannerOpenApi.Configure(options));
    }

    /// <summary>Maps scanner controller routes and enables the developer exception page in Development.</summary>
    /// <param name="app">The application request pipeline.</param>
    /// <param name="environment">The hosting environment used to select exception-page behavior.</param>
    public void Configure(IApplicationBuilder app, IWebHostEnvironment environment)
    {
        if (environment.IsDevelopment())
            app.UseDeveloperExceptionPage();

        app.UseRouting();
        app.UseEndpoints(endpoints => endpoints.MapControllers());
    }
}

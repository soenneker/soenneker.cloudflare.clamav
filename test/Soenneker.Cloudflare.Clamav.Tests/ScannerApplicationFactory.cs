using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Hosts the real HTTP and service graph without launching native child processes.</summary>
public sealed class ScannerApplicationFactory : WebApplicationFactory<Program>
{
    public const string ApiKey = "scanner-test-key-at-least-32-characters";
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Scanner:ApiKey"] = ApiKey,
            ["Scanner:MaximumFileSize"] = "16",
            ["Cloudflare:RequestResponseLogging"] = "true"
        }));
        // Native process behavior is exercised against the published Linux image by container-smoke.py.
        builder.ConfigureServices(services => services.RemoveAll<IHostedService>());
    }
    public T Resolve<T>() where T : notnull => Services.GetRequiredService<T>();
}

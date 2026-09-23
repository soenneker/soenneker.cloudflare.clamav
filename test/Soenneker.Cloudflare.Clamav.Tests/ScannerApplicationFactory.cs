using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Soenneker.Cloudflare.Clamav.Tests;

/// <summary>Hosts the real scanner service graph in memory with isolated test configuration.</summary>
/// <remarks>Storage credentials are placeholders; tests reject requests before making external storage or scanning calls.</remarks>
public sealed class ScannerApplicationFactory : WebApplicationFactory<Program>
{
    /// <summary>Sets production request handling, a test API key, and a small upload limit.</summary>
    /// <param name="builder">The test host builder to configure.</param>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Scanner:ApiKey"] = "scanner-test-key",
                ["Scanner:MaximumFileSize"] = "16",
                ["Scanner:R2:Bucket"] = "scanner-tests",
                ["Cloudflare:AccountId"] = "test-account",
                ["Cloudflare:ApiKey"] = "test-key",
                ["Cloudflare:RequestResponseLogging"] = "true"
            }));
    }
}

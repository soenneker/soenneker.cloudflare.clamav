using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>
/// Provides the application entry point.
/// </summary>
public sealed class Program
{
    /// <summary>Builds and runs the scanner host until shutdown is requested.</summary>
    /// <param name="args">Command-line arguments passed to the default host configuration.</param>
    /// <returns>A task that completes when the host shuts down.</returns>
    public static Task Main(string[] args) => CreateHostBuilder(args).Build().RunAsync();

    /// <summary>
    /// Creates the application host.
    /// </summary>
    /// <param name="args">Command-line arguments passed to the default host configuration.</param>
    /// <returns>An unbuilt host builder configured to use <see cref="Startup"/>.</returns>
    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
}

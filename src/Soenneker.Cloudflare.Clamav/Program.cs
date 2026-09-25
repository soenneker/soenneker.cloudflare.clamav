using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>Provides the application entry point.</summary>
public sealed class Program
{
    /// <summary>Builds and runs the scanner host until shutdown is requested.</summary>
    /// <param name="args">Command-line arguments passed to the host configuration.</param>
    /// <returns>A task that completes when the host shuts down.</returns>
    public static Task Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);
        var startup = new Startup(builder.Configuration);
        startup.ConfigureServices(builder.Services);
        WebApplication app = builder.Build();
        startup.Configure(app, app.Environment);
        return app.RunAsync();
    }
}

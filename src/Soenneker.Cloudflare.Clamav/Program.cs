using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;

namespace Soenneker.Cloudflare.Clamav;

/// <summary>Runs the scanner host or the container readiness probe.</summary>
public sealed class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args is ["--healthcheck"])
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Environment.GetEnvironmentVariable("Scanner__ApiKey"));
                using HttpResponseMessage response = await client.GetAsync("http://127.0.0.1:8080/ready");
                return response.IsSuccessStatusCode ? 0 : 1;
            }
            catch { return 1; }
        }
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);
        var startup = new Startup(builder.Configuration);
        startup.ConfigureServices(builder.Services);
        WebApplication app = builder.Build();
        startup.Configure(app, app.Environment);
        await app.RunAsync();
        return 0;
    }
}

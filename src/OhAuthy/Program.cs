using Microsoft.Extensions.Configuration;

namespace Ww.OhAuthy;

internal class Program
{
    static async Task Main(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile("appsettings.local.json", optional: false)
            .Build();

        await new Auth0Runner().RunAsync(config.GetSection("Auth0"));
    }
}

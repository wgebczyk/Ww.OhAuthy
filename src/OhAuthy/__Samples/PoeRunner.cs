using Microsoft.Extensions.Configuration;

namespace Ww.OhAuthy;

public record PoeOptions
{
    public string AuthorizeUrl { get; init; } = string.Empty;
    public string TokenUrl { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string RedirectUri { get; init; } = string.Empty;
    public string[] Scopes { get; init; } = [];
    public string UserAgent { get; init; } = string.Empty;
}

public sealed class PoeRunner
{
    private readonly PoeOptions _options = new();
    private LocalhostAuthenticationClient _authenticationClient = default!;

    private AuthorizationCodeFlowSettings _authCodeSettings = default!;
    private AuthenticationCode _authCode = default!;
    private AuthorizationCodeExchangeTokenFlowSettings _codeExchangeTokenSettings = default!;
    private AuthenticationToken _authToken = default!;
    private TokenRefreshFlowSettings _tokenRefreshSettings = default!;
    private AuthenticationToken _authTokenRefreshed = default!;

    public async Task RunAsync(IConfigurationSection configuration)
    {
        configuration.Bind(_options);

        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(10) };
        _authenticationClient = new LocalhostAuthenticationClient(
            new HttpClient(handler),
            new WindowsPlatformProxy()
        );

        await RunAuthCodeFlowAsync();
        await RunCodeExchangeTokenFlowAsync();
        await RunTokenRefreshFlowAsync();
    }

    private async Task RunAuthCodeFlowAsync()
    {
        _authCodeSettings = new AuthorizationCodeFlowSettings(
            authorizeUrl: _options.AuthorizeUrl,
            clientId: _options.ClientId,
            redirectUrl: _options.RedirectUri,
            scopes: _options.Scopes
        );

        var res = await _authenticationClient.ExecuteAuthorizationCodeFlowAsync(_authCodeSettings, CancellationToken.None);
        if (res is AuthenticationCode code)
        {
            _authCode = code;
            Console.WriteLine($"(PoeRunner) (1) Code: {_authCode.Code}");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(PoeRunner) (1) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(PoeRunner) (1) INTERNAL ERROR.");
        }
    }

    private async Task RunCodeExchangeTokenFlowAsync()
    {
        _codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
            tokenUrl: _options.TokenUrl,
            _authCodeSettings,
            _authCode
        )
        {
            SendOrigin = true,
            SendHeaders = new Dictionary<string, string>
            {
                ["User-Agent"] = _options.UserAgent
            },
        };

        var res = await _authenticationClient.ExecuteAuthorizationCodeExchangeTokenFlowAsync(
            _codeExchangeTokenSettings,
            CancellationToken.None
        );
        if (res is AuthenticationToken token)
        {
            _authToken = token;
            Console.WriteLine($"(PoeRunner) (2) AccessToken: {_authToken.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(PoeRunner) (2) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(PoeRunner) (2) INTERNAL ERROR.");
        }
    }

    private async Task RunTokenRefreshFlowAsync()
    {
        _tokenRefreshSettings = new TokenRefreshFlowSettings(
            tokenUrl: _options.TokenUrl,
            _authCodeSettings,
            _authToken
        )
        {
            RedirectUri = _options.RedirectUri,
            SendOrigin = true,
            SendHeaders = new Dictionary<string, string>
            {
                ["User-Agent"] = _options.UserAgent
            },
        };

        var res = await _authenticationClient.ExecuteTokenRefreshFlowAsync(_tokenRefreshSettings, CancellationToken.None);
        if (res is AuthenticationToken token)
        {
            _authTokenRefreshed = token;
            Console.WriteLine($"(PoeRunner) (3) AccessToken: {_authTokenRefreshed.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(PoeRunner) (3) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(PoeRunner) (3) INTERNAL ERROR.");
        }
    }
}

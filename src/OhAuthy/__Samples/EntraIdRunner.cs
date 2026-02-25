using Microsoft.Extensions.Configuration;

namespace Ww.OhAuthy;

public record EntraIdOptions
{
    public string AuthorizeUrl { get; init; } = string.Empty;
    public string TokenUrl { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string RedirectUri { get; init; } = string.Empty;
    public string[] Scopes { get; init; } = [];
}

public sealed class EntraIdRunner
{
    private readonly EntraIdOptions _options = new();
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
            Console.WriteLine($"(EntraIdRunner) (1) Code: {_authCode.Code}");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(EntraIdRunner) (1) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(EntraIdRunner) (1) INTERNAL ERROR.");
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
            SendOrigin = true
        };

        var res = await _authenticationClient.ExecuteAuthorizationCodeExchangeTokenFlowAsync(
            _codeExchangeTokenSettings,
            CancellationToken.None
        );
        if (res is AuthenticationToken token)
        {
            _authToken = token;
            Console.WriteLine($"(EntraIdRunner) (2) AccessToken: {_authToken.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(EntraIdRunner) (2) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(EntraIdRunner) (2) INTERNAL ERROR.");
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
        };

        var res = await _authenticationClient.ExecuteTokenRefreshFlowAsync(_tokenRefreshSettings, CancellationToken.None);
        if (res is AuthenticationToken token)
        {
            _authTokenRefreshed = token;
            Console.WriteLine($"(EntraIdRunner) (3) AccessToken: {_authTokenRefreshed.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(EntraIdRunner) (3) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(EntraIdRunner) (3) INTERNAL ERROR.");
        }
    }
}

using Microsoft.Extensions.Configuration;

namespace Ww.OhAuthy;

public record Auth0Options
{
    public string AuthorizeUrl { get; init; } = string.Empty;
    public string TokenUrl { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string RedirectUrl { get; init; } = string.Empty;
    public string[] Scopes { get; init; } = [];
}

public sealed class Auth0Runner
{
    private readonly Auth0Options _options = new();
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
            redirectUrl: _options.RedirectUrl,
            scopes: _options.Scopes
        );

        var res = await _authenticationClient.ExecuteAuthorizationCodeFlowAsync(_authCodeSettings, CancellationToken.None);
        if (res is AuthenticationCode code)
        {
            _authCode = code;
            Console.WriteLine($"(Auth0Runner) (1) Code: {_authCode.Code}");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(Auth0Runner) (1) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(Auth0Runner) (1) INTERNAL ERROR.");
        }
    }

    private async Task RunCodeExchangeTokenFlowAsync()
    {
        _codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
            tokenUrl: _options.TokenUrl,
            _authCodeSettings,
            _authCode
        );

        var res = await _authenticationClient.ExecuteAuthorizationCodeExchangeTokenFlowAsync(
            _codeExchangeTokenSettings,
            CancellationToken.None
        );

        if (res is AuthenticationToken token)
        {
            _authToken = token;
            Console.WriteLine($"(Auth0Runner) (2) AccessToken: {_authToken.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(Auth0Runner) (2) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(Auth0Runner) (2) INTERNAL ERROR.");
        }
    }

    private async Task RunTokenRefreshFlowAsync()
    {
        _tokenRefreshSettings = new TokenRefreshFlowSettings(
            tokenUrl: _options.TokenUrl,
            _authCodeSettings,
            _authToken
        );

        var res = await _authenticationClient.ExecuteTokenRefreshFlowAsync(_tokenRefreshSettings, CancellationToken.None);

        if (res is AuthenticationToken token)
        {
            _authTokenRefreshed = token;
            Console.WriteLine($"(Auth0Runner) (3) AccessToken: {_authTokenRefreshed.AccessToken})");
        }
        else if (res is AuthenticationError error)
        {
            Console.WriteLine($"(Auth0Runner) (3) Error: {error.Error} ({error.ErrorDescription})");
        }
        else
        {
            Console.WriteLine($"(Auth0Runner) (3) INTERNAL ERROR.");
        }
    }
}

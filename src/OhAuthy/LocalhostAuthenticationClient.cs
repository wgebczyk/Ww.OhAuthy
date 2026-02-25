using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net.Http.Json;
using System.Text.Json.Nodes;

namespace Ww.OhAuthy;

public sealed class LocalhostAuthenticationClient
{
    private readonly HttpClient httpClient;
    private readonly IPlatformProxy platformProxy;

    public LocalhostAuthenticationClient(HttpClient httpClient, IPlatformProxy platformProxy)
    {
        this.httpClient = httpClient;
        this.platformProxy = platformProxy;
    }

    public async Task<AuthenticationResult> ExecuteAuthorizationCodeFlowAsync(
        AuthorizationCodeFlowSettings settings,
        CancellationToken cancellationToken)
    {
        var parameters = settings.CreateParameters();

        var authentication = new LocalhostBrowserAuthentication(
            platformProxy,
            NullLogger<LocalhostAuthenticationClient>.Instance
        );

        var authResult = await authentication.AcquireAuthorizationAsync(
            new Uri(QueryHelpers.AddQueryString(settings.AuthorizeUrl, parameters)),
            new Uri(settings.RedirectUrl),
            cancellationToken
        );

        if (authResult is AuthenticationCode authCode)
        {
            return new AuthenticationCode(
                authCode.RequestUri,
                authCode.Code,
                authCode.State
            );
        }
        else if (authResult is AuthenticationError authError)
        {
            return new AuthenticationError(authError.RequestUri, authError.Error, authError.ErrorDescription);
        }
        else
        {
            throw new NotImplementedException();
        }
    }

    public async Task<AuthenticationResult> ExecuteImplicitFlowAsync(
        ImplicitFlowSettings settings,
        CancellationToken cancellationToken)
    {
        var parameters = settings.CreateParameters();

        var authentication = new LocalhostBrowserAuthentication(
            new WindowsPlatformProxy(),
            NullLogger<LocalhostBrowserAuthentication>.Instance
        );

        var authResult = await authentication.AcquireAuthorizationAsync(
            new Uri(QueryHelpers.AddQueryString(settings.AuthorizeUrl, parameters)),
            new Uri(settings.RedirectUri),
            cancellationToken
        );

        if (authResult is AuthenticationToken authToken)
        {
            return new AuthenticationToken(
                authToken.RequestUri,
                authToken.TokenType,
                authToken.Scope,
                authToken.ExpiresIn,
                authToken.AccessToken
            )
            {
                RefreshToken = authToken.RefreshToken,
                IdToken = authToken.IdToken,
                Other = authToken.Other,
            };
        }
        else if (authResult is AuthenticationError authError)
        {
            return new AuthenticationError(authError.RequestUri, authError.Error, authError.ErrorDescription);
        }
        else
        {
            throw new NotImplementedException();
        }
    }

    public Task<AuthenticationResult> ExecuteAuthorizationCodeExchangeTokenFlowAsync(AuthorizationCodeExchangeTokenFlowSettings settings, CancellationToken cancellationToken)
    {
        return ExecuteTokenFormEncodedFlowAsync(settings, cancellationToken);
    }

    public Task<AuthenticationResult> ExecuteTokenRefreshFlowAsync(TokenRefreshFlowSettings settings, CancellationToken cancellationToken)
    {
        return ExecuteTokenFormEncodedFlowAsync(settings, cancellationToken);
    }

    private async Task<AuthenticationResult> ExecuteTokenFormEncodedFlowAsync(ITokenBasedFlowSettings settings, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(settings.TokenUrl),
            Content = new FormUrlEncodedContent(settings.CreateParameters())
        };
        foreach (var header in settings.CreateHeaders())
        {
            request.Headers.Add(header.Key, header.Value);
        }

        using var response = await httpClient.SendAsync(request, cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken);
            return AuthenticationToken.FromJson(request.RequestUri, json!);
        }
        else
        {
            return new AuthenticationError(request.RequestUri, "UnknownError", await response.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}
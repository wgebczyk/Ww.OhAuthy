using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Ww.OhAuthy;

namespace Ww.OhAuthy2;

public sealed class AuthorizationCodeFlowSettings(
    string authorizeUrl,
    string clientId,
    string redirectUrl,
    IReadOnlyList<string> scopes)
{
    public string AuthorizeUrl { get; } = authorizeUrl;
    public string ClientId { get; } = clientId;
    public string RedirectUrl { get; } = redirectUrl;
    public IReadOnlyList<string> Scopes { get; } = scopes;

    public string? State { get; set; }

    private const string AuthorizationCodeFlowResponseType = "code";

    public IDictionary<string, string?> CreateParameters()
    {
        return new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["response_type"] = AuthorizationCodeFlowResponseType,
            ["redirect_uri"] = RedirectUrl,
            ["scope"] = string.Join(' ', Scopes),
            ["state"] = State ?? GetRandomState(),
        };
    }

    private const int DefaultStateSize = 16;
    private static string GetRandomState()
    {
        var randomBytes = new byte[DefaultStateSize];
        RandomNumberGenerator.Create().GetBytes(randomBytes);
        return WebEncoders.Base64UrlEncode(randomBytes);
    }
}
public sealed class ImplicitFlowSettings(
    string authorizeUrl,
    string clientId,
    string redirectUrl,
    IReadOnlyList<string> scopes)
{
    public string AuthorizeUrl { get; } = authorizeUrl;
    public string ClientId { get; } = clientId;
    public string RedirectUrl { get; } = redirectUrl;
    public IReadOnlyList<string> Scopes { get; } = scopes;

    private const string ImplicitFlowResponseType = "token";

    public IDictionary<string, string?> CreateParameters()
    {
        return new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["response_type"] = ImplicitFlowResponseType,
            ["redirect_uri"] = RedirectUrl,
            ["scope"] = string.Join(' ', Scopes),
        };
    }
}

public abstract class AuthenticationResult(Uri requestUri)
{
    public Uri RequestUri { get; } = requestUri;
}
public sealed class AuthenticationError(Uri requestUri, string error, string errorDescription) : AuthenticationResult(requestUri)
{
    public string Error { get; } = error;
    public string ErrorDescription { get; } = errorDescription;
}
public sealed class AuthenticationCode(
    Uri requestUri,
    string code,
    string state,
    string pkceChallenge,
    string pkceVerifier
) : AuthenticationResult(requestUri)
{
    public string Code { get; } = code;

    public string State { get; } = state;
    public string PkceChallenge { get; } = pkceChallenge;
    public string PkceVerifier { get; } = pkceVerifier;
}
public sealed class AuthenticationToken(
    Uri requestUri,
    string tokenType,
    string scope,
    long expiresIn,
    string accessToken,
    string? refreshToken = null,
    string? idToken = null
) : AuthenticationResult(requestUri)
{
    public string TokenType { get; } = tokenType;
    public string Scope { get; } = scope;
    public long ExpiresIn { get; } = expiresIn;

    public string AccessToken { get; } = accessToken;
    public string? RefreshToken { get; init; } = refreshToken;
    public string? IdToken { get; init; } = idToken;
}

public sealed class LocalhostAuthClient
{
    private const int DefaultPkceSize = 32;
    private static (string challenge, string verifier) GeneratePkce(int size)
    {
        var randomBytes = new byte[size];
        RandomNumberGenerator.Create().GetBytes(randomBytes);
        var verifier = WebEncoders.Base64UrlEncode(randomBytes);

        var buffer = Encoding.UTF8.GetBytes(verifier);
        var hash = SHA256.HashData(buffer);
        var challenge = WebEncoders.Base64UrlEncode(hash);

        return (challenge, verifier);
    }

    public async Task<AuthenticationResult> ExecuteAuthorizationCodeFlowAsync(
        AuthorizationCodeFlowSettings settings,
        CancellationToken cancellationToken)
    {
        var parameters = settings.CreateParameters();
        var state = parameters["state"] ?? throw new InvalidOperationException("State parameter is required.");

        (var challenge, var verifier) = GeneratePkce(DefaultPkceSize);
        parameters["code_challenge"] = challenge;
        parameters["code_challenge_method"] = "S256";

        var authentication = new LocalhostBrowserAuthentication(
            new WindowsPlatformProxy(),
            NullLogger<LocalhostBrowserAuthentication>.Instance
        );

        var authResult = await authentication.AcquireAuthorizationAsync(
            new Uri(QueryHelpers.AddQueryString(settings.AuthorizeUrl, parameters)),
            new Uri(settings.RedirectUrl),
            cancellationToken
        );

        if (authResult is AuthCode authCode)
        {
            return new AuthenticationCode(
                authCode.RequestUri,
                authCode.Code,
                state,
                challenge,
                verifier
            );
        }
        else if (authResult is AuthError authError)
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
            new Uri(settings.RedirectUrl),
            cancellationToken
        );

        if (authResult is AuthToken authToken)
        {
            return new AuthenticationToken(
                authToken.RequestUri,
                authToken.TokenType,
                authToken.Scope,
                authToken.ExpiresIn,
                authToken.AccessToken,
                authToken.RefreshToken,
                authToken.IdToken
            );
        }
        else if (authResult is AuthError authError)
        {
            return new AuthenticationError(authError.RequestUri, authError.Error, authError.ErrorDescription);
        }
        else
        {
            throw new NotImplementedException();
        }
    }


    private string? _tokenUrl;
    private readonly Dictionary<string, string> _tokenHeaders = new();
    private string? _tokenClientSecret;
    private bool _sendTokenOrigin = false;



    public LocalhostAuthBuilder UseTokenEndpoint(string tokenUrl)
    {
        _tokenUrl = tokenUrl;
        return this;
    }

    public LocalhostAuthBuilder SendTokenHeader(string headerKey, string headerValue)
    {
        _tokenHeaders[headerKey] = headerValue;
        return this;
    }

    public LocalhostAuthBuilder SendTokenClientSecret(string clientSecret)
    {
        _tokenClientSecret = clientSecret;
        return this;
    }

    public LocalhostAuthBuilder SendTokenOrigin()
    {
        _sendTokenOrigin = true;
        return this;
    }

    public async Task<AuthResult> ExecuteAsync(CancellationToken cancellationToken)
    {
        var authResult = await AuthorizeExecuteAsync(cancellationToken);

        if (authResult is AuthError error)
        {
            return error;
        }
        if (authResult is AuthToken token)
        {
            return token;
        }

        if (authResult is AuthCode success)
        {
            return await TokenExecuteAsync(success.Code, cancellationToken);
        }

        throw new NotImplementedException();
    }

    private async Task<AuthResult> AuthorizeExecuteAsync(CancellationToken cancellationToken)
    {
        return await new LocalhostBrowserAuthentication(
            new WindowsPlatformProxy(),
            NullLogger<LocalhostBrowserAuthentication>.Instance
        ).AcquireAuthorizationAsync(
            new Uri(QueryHelpers.AddQueryString(_authorizeUrl, _authorizeParameters)),
            new Uri(_redirectUrl),
            cancellationToken
        );
    }

    private async Task<AuthResult> TokenExecuteAsync(string code, CancellationToken cancellationToken)
    {
        if (_tokenUrl is null)
        {
            throw new InvalidOperationException("Token URL is not defined.");
        }

        var formData = new Dictionary<string, string?>
        {
            ["client_id"] = _clientId,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = _redirectUrl,
            ["scope"] = string.Join(' ', _scopes),
            ["code_verifier"] = _verifier,
        };
        if (_tokenClientSecret is not null)
        {
            formData["client_secret"] = _tokenClientSecret;
        }

        using var client = new HttpClient();
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(_tokenUrl),
            Content = new FormUrlEncodedContent(formData)
        };
        if (_sendTokenOrigin)
        {
            var originUrl = new UriBuilder(_redirectUrl)
            {
                Query = string.Empty,
                Fragment = string.Empty,
                Path = string.Empty
            };
            request.Headers.Add("Origin", originUrl.ToString());
        }
        foreach (var header in _tokenHeaders)
        {
            request.Headers.Add(header.Key, header.Value);
        }

        using var response = await client.SendAsync(request);

        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadFromJsonAsync<JsonObject>();
            return AuthToken.FromJson(request.RequestUri, json!);
        }
        else
        {
            return AuthResult.CreateError(request.RequestUri, "UnknownError", await response.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Ww.OhAuthy;

public sealed class LocalhostAuthBuilder
{
    private const int DefaultPkceSize = 32;
    private const int DefaultStateSize = 16;

    private const string AuthorizationCodeFlowResponseType = "code";
    private const string ImplicitFlowResponseType = "token";

    private readonly string _authorizeUrl;
    private readonly string _clientId;
    private readonly string _redirectUrl;
    private readonly IReadOnlyList<string> _scopes;
    private readonly Dictionary<string, string?> _authorizeParameters = new();

    private string? _tokenUrl;
    private readonly Dictionary<string, string> _tokenHeaders = new();
    private string? _tokenClientSecret;
    private bool _sendTokenOrigin = false;

    private readonly string _verifier;

    private LocalhostAuthBuilder(
        string authorizeUrl,
        string clientId,
        string redirectUrl,
        string responseType,
        bool usePkce,
        IReadOnlyList<string> scopes)
    {
        _authorizeUrl = authorizeUrl;
        _clientId = clientId;
        _redirectUrl = redirectUrl;
        _scopes = scopes;

        (var challenge, var verifier) = GeneratePkce(DefaultPkceSize);
        _verifier = verifier;

        _authorizeParameters = new Dictionary<string, string?>
        {
            ["client_id"] = _clientId,
            ["response_type"] = responseType,
            ["redirect_uri"] = redirectUrl,
            ["scope"] = string.Join(' ', scopes),
        };
        if (usePkce)
        {
            _authorizeParameters["code_challenge"] = challenge;
            _authorizeParameters["code_challenge_method"] = "S256";
        }
    }

    public static LocalhostAuthBuilder UseAuthorizationCodeFlow(
        string authorizeUrl,
        string clientId,
        string redirectUri,
        IReadOnlyList<string> scopes
    )
    {
        return new LocalhostAuthBuilder(
            authorizeUrl,
            clientId,
            redirectUri,
            AuthorizationCodeFlowResponseType,
            usePkce: true,
            scopes
        );
    }

    public static LocalhostAuthBuilder UseImplicitFlow(
        string authorizeUrl,
        string clientId,
        string redirectUri,
        IReadOnlyList<string> scopes
    )
    {
        return new LocalhostAuthBuilder(
            authorizeUrl,
            clientId,
            redirectUri,
            ImplicitFlowResponseType,
            usePkce: false,
            scopes
        );
    }

    public LocalhostAuthBuilder SendAuthorizeState()
    {
        var randomBytes = new byte[DefaultStateSize];
        RandomNumberGenerator.Create().GetBytes(randomBytes);
        _authorizeParameters["state"] = WebEncoders.Base64UrlEncode(randomBytes);
        return this;
    }

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

    private static (string challenge, string verifier) GeneratePkce(int size)
    {
        var randomBytes = new byte[size];
        RandomNumberGenerator.Create().GetBytes(randomBytes);
        var verifier = WebEncoders.Base64UrlEncode(randomBytes);

        var buffer = Encoding.UTF8.GetBytes(verifier);
        var hash = SHA256.Create().ComputeHash(buffer);
        var challenge = WebEncoders.Base64UrlEncode(hash);

        return (challenge, verifier);
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
namespace Ww.OhAuthy;

using KeyValue = KeyValuePair<string, string?>;

public sealed class AuthorizationCodeExchangeTokenFlowSettings : ITokenBasedFlowSettings
{
    private const string AuthorizationCodeExchangeTokenFlowGrantType = "authorization_code";

    public AuthorizationCodeExchangeTokenFlowSettings(
        string tokenUrl,
        string clientId,
        string redirectUri,
        string code,
        string pkceVerifier,
        IReadOnlyList<string> scopes)
    {
        TokenUrl = tokenUrl;
        ClientId = clientId;
        RedirectUri = redirectUri;
        Code = code;
        PkceVerifier = pkceVerifier;
        Scopes = scopes;
    }
    public AuthorizationCodeExchangeTokenFlowSettings(
        string tokenUrl,
        AuthorizationCodeFlowSettings authorizationCodeFlowSettings,
        AuthenticationCode authenticationCode)
    {
        TokenUrl = tokenUrl;
        ClientId = authorizationCodeFlowSettings.ClientId;
        RedirectUri = authorizationCodeFlowSettings.RedirectUrl;
        Code = authenticationCode.Code;
        PkceVerifier = authorizationCodeFlowSettings.PkceVerifier;
        Scopes = authorizationCodeFlowSettings.Scopes;
    }

    public string TokenUrl { get; }
    public string ClientId { get; }
    public string? ClientSecret { get; set; }
    public string RedirectUri { get; }
    public string Code { get; }
    public string PkceVerifier { get; }
    public IReadOnlyList<string> Scopes { get; }

    public bool SendOrigin { get; set; } = false;
    public IReadOnlyDictionary<string, string> SendHeaders { get; set; } = new Dictionary<string, string>();

    public IEnumerable<KeyValue> CreateParameters()
    {
        yield return new KeyValue("client_id", ClientId);
        yield return new KeyValue("grant_type", AuthorizationCodeExchangeTokenFlowGrantType);
        yield return new KeyValue("code", Code);
        yield return new KeyValue("redirect_uri", RedirectUri);
        yield return new KeyValue("scope", string.Join(' ', Scopes));
        yield return new KeyValue("code_verifier", PkceVerifier);

        if (ClientSecret is not null)
        {
            yield return new KeyValue("client_secret", ClientSecret);
        }
    }

    public IEnumerable<KeyValue> CreateHeaders()
    {
        if (SendOrigin)
        {
            var originUrl = new UriBuilder(RedirectUri)
            {
                Query = string.Empty,
                Fragment = string.Empty,
                Path = string.Empty
            };
            yield return new KeyValue("Origin", originUrl.ToString());
        }
        foreach (var header in SendHeaders)
        {
            yield return new KeyValue(header.Key, header.Value);
        }
    }
}

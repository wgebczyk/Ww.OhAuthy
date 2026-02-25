namespace Ww.OhAuthy;

using KeyValue = KeyValuePair<string, string?>;

public sealed class TokenRefreshFlowSettings : ITokenBasedFlowSettings
{
    private const string TokenRefreshFlowResponseType = "refresh_token";

    public TokenRefreshFlowSettings(
        string tokenUrl,
        string clientId,
        string refreshToken,
        IReadOnlyList<string> scopes)
    {
        TokenUrl = tokenUrl;
        ClientId = clientId;
        RefreshToken = refreshToken;
        Scopes = scopes;
    }

    public TokenRefreshFlowSettings(
        string tokenUrl,
        AuthorizationCodeFlowSettings authorizationCodeFlowSettings,
        AuthenticationToken authenticationToken)
    {
        TokenUrl = tokenUrl;
        ClientId = authorizationCodeFlowSettings.ClientId;
        RefreshToken = authenticationToken.RefreshToken ?? throw new ArgumentNullException(nameof(authenticationToken));
        Scopes = authorizationCodeFlowSettings.Scopes;
    }

    public string TokenUrl { get; }
    public string ClientId { get; }
    public string? ClientSecret { get; set; }
    public string? RedirectUri { get; set; }
    public string RefreshToken { get; }
    public IReadOnlyList<string> Scopes { get; }

    public bool SendOrigin { get; set; } = false;
    public IReadOnlyDictionary<string, string> SendHeaders { get; set; } = new Dictionary<string, string>();

    public IEnumerable<KeyValue> CreateParameters()
    {
        yield return new KeyValue("client_id", ClientId);
        yield return new KeyValue("grant_type", TokenRefreshFlowResponseType);
        yield return new KeyValue("refresh_token", RefreshToken);
        yield return new KeyValue("scope", string.Join(' ', Scopes));
    }

    public IEnumerable<KeyValue> CreateHeaders()
    {
        if (SendOrigin)
        {
            ArgumentNullException.ThrowIfNull(RedirectUri, "Redirect URI must be set when SendOrigin is true.");

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

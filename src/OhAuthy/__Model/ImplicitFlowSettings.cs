namespace Ww.OhAuthy;

using KeyValue = KeyValuePair<string, string?>;

public sealed class ImplicitFlowSettings(
    string authorizeUrl,
    string clientId,
    string redirectUri,
    IReadOnlyList<string> scopes)
{
    public string AuthorizeUrl { get; } = authorizeUrl;
    public string ClientId { get; } = clientId;
    public string RedirectUri { get; } = redirectUri;
    public IReadOnlyList<string> Scopes { get; } = scopes;

    private const string ImplicitFlowResponseType = "token";

    public IEnumerable<KeyValue> CreateParameters()
    {
        yield return new KeyValue("client_id", ClientId);
        yield return new KeyValue("response_type", ImplicitFlowResponseType);
        yield return new KeyValue("redirect_uri", RedirectUri);
        yield return new KeyValue("scope", string.Join(' ', Scopes));
    }

    public IEnumerable<KeyValue> CreateHeaders()
    {
        yield break;
    }
}

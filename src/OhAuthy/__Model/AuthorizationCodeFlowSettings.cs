using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text;

namespace Ww.OhAuthy;

using KeyValue = KeyValuePair<string, string?>;

public sealed class AuthorizationCodeFlowSettings
{
    private const string AuthorizationCodeFlowResponseType = "code";

    public AuthorizationCodeFlowSettings(
        string authorizeUrl,
        string clientId,
        string redirectUrl,
        IReadOnlyList<string> scopes)
    {
        AuthorizeUrl = authorizeUrl;
        ClientId = clientId;
        RedirectUrl = redirectUrl;
        Scopes = scopes;

        State = GetRandomState();

        var (challenge, verifier) = GeneratePkce(DefaultPkceSize);
        PkceChallenge = challenge;
        PkceVerifier = verifier;
    }

    public string AuthorizeUrl { get; }
    public string ClientId { get; }
    public string RedirectUrl { get; }
    public IReadOnlyList<string> Scopes { get; }

    public string State { get; set; }

    public bool UsePkce { get; set; } = true;
    public string PkceChallenge { get; }
    public string PkceVerifier { get; }

    public IEnumerable<KeyValue> CreateParameters()
    {
        yield return new KeyValue("client_id", ClientId);
        yield return new KeyValue("response_type", AuthorizationCodeFlowResponseType);
        yield return new KeyValue("redirect_uri", RedirectUrl);
        yield return new KeyValue("scope", string.Join(' ', Scopes));
        yield return new KeyValue("state", State ?? GetRandomState());

        if (UsePkce)
        {
            yield return new KeyValue("code_challenge", PkceChallenge);
            yield return new KeyValue("code_challenge_method", "S256");
        }
    }

    public IEnumerable<KeyValue> CreateHeaders()
    {
        yield break;
    }

    private const int DefaultStateSize = 16;

    private static string GetRandomState()
    {
        var randomBytes = new byte[DefaultStateSize];
        RandomNumberGenerator.Create().GetBytes(randomBytes);
        return WebEncoders.Base64UrlEncode(randomBytes);
    }

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
}

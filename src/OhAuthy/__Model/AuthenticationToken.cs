using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ww.OhAuthy;

public sealed class AuthenticationToken(
    Uri requestUri,
    string tokenType,
    string scope,
    long expiresIn,
    string accessToken
) : AuthenticationResult(requestUri)
{
    public string TokenType { get; } = tokenType;
    public string Scope { get; } = scope;
    public long ExpiresIn { get; } = expiresIn;

    public string AccessToken { get; } = accessToken;
    public string? RefreshToken { get; set; }
    public string? IdToken { get; set; }

    public required IReadOnlyDictionary<string, JsonElement> Other { get; set; } = new Dictionary<string, JsonElement>();

    private static readonly HashSet<string> KnownProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "token_type",
        "scope",
        "expires_in",
        "access_token",
        "refresh_token",
        "id_token"
    };

    public static AuthenticationToken FromJson(Uri requestUri, JsonObject json)
    {
        return new AuthenticationToken(
            requestUri: requestUri,
            tokenType: GetPropertyString(json, "token_type"),
            scope: GetPropertyString(json, "scope"),
            expiresIn: GetPropertyNumber(json, "expires_in"),
            accessToken: GetPropertyString(json, "access_token")
        )
        {
            RefreshToken = GetOptionalPropertyValue(json, "refresh_token"),
            IdToken = GetOptionalPropertyValue(json, "id_token"),
            Other = json
                .Where(x => !KnownProperties.Contains(x.Key))
                .ToDictionary(x => x.Key, x => x.Value!.AsValue().GetValue<JsonElement>()),
        };
    }
    private static string GetPropertyString(JsonObject json, string propertyName)
    {
        if (!json.TryGetPropertyValue(propertyName, out var jsonElement))
        {
            throw new Exception($"Missing required parameter: {propertyName}");
        }
        var value = jsonElement!.GetValue<string>();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new Exception($"Missing required property: {propertyName}");
        }
        return value;
    }
    private static long GetPropertyNumber(JsonObject json, string propertyName)
    {
        if (!json.TryGetPropertyValue(propertyName, out var jsonElement))
        {
            throw new Exception($"Missing required parameter: {propertyName}");
        }
        return jsonElement!.GetValue<long>();
    }
    private static string? GetOptionalPropertyValue(JsonObject json, string propertyName, string? defaultValue = null)
    {
        if (!json.TryGetPropertyValue(propertyName, out var jsonElement))
        {
            return defaultValue;
        }
        var value = jsonElement!.GetValue<string>();
        return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
    }
}

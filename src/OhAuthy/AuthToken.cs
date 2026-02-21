using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ww.OhAuthy;

public sealed class AuthToken : AuthResult
{
    public required string TokenType { get; init; }
    public required string Scope { get; init; }
    public required long ExpiresIn { get; init; }

    public required string AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }

    public required IReadOnlyDictionary<string, JsonElement> Other { get; init; }

    private static readonly HashSet<string> KnownProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "token_type",
        "scope",
        "expires_in",
        "access_token",
        "refresh_token",
        "id_token"
    };
    public static AuthToken FromJson(Uri requestUri, JsonObject json)
    {
        var other = json.Where(x => !KnownProperties.Contains(x.Key))
            .ToDictionary(x => x.Key, x => x.Value!.AsValue().GetValue<JsonElement>());
        return new AuthToken
        {
            RequestUri = requestUri,
            TokenType = GetPropertyString(json, "token_type"),
            Scope = GetPropertyString(json, "scope"),
            ExpiresIn = GetPropertyNumber(json, "expires_in"),
            AccessToken = GetPropertyString(json, "access_token"),
            RefreshToken = GetOptionalPropertyValue(json, "refresh_token"),
            IdToken = GetOptionalPropertyValue(json, "id_token"),
            Other = other
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

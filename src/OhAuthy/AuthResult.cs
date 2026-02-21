using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ww.OhAuthy;

public abstract class AuthResult
{
    [JsonIgnore]
    public required Uri RequestUri { get; set; }

    public static AuthResult FromUri(Uri requestUri)
    {
        string query = requestUri.Query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(query))
        {
            return CreateError(requestUri, "UnknownError", "The authorization server returned an invalid response.");
        }

        return CreateFromParameters(requestUri, QueryHelpers.ParseQuery(query));
    }

    public static AuthResult FromPostData(Uri requestUri, byte[] postData)
    {
        if (postData == null)
        {
            return CreateError(requestUri, "UnknownError", "The authorization server returned an invalid response.");
        }

        return CreateFromParameters(requestUri, QueryHelpers.ParseQuery(Encoding.Default.GetString(postData).TrimEnd('\0')));
    }

    private static AuthResult CreateFromParameters(Uri requestUri, Dictionary<string, StringValues> parameters)
    {
        if (TryGetParameterValue(parameters, "error", out var error))
        {
            var errorDescription = GetParameterValue(parameters, "error_description", "Generic error");
            return CreateError(requestUri, "ProtocolError", errorDescription);
        }

        if (TryGetParameterValue(parameters, "access_token", out var accessToken))
        {
            return CreateAuthToken(requestUri, accessToken, parameters);
        }

        return CreateAuthCode(requestUri, parameters);
    }

    private static AuthCode CreateAuthCode(Uri requestUri, Dictionary<string, StringValues> parameters)
    {
        var code = GetParameterValue(parameters, "code");
        _ = TryGetParameterValue(parameters, "state", out var state);

        return new AuthCode
        {
            RequestUri = requestUri,
            Code = code,
            State = state
        };
    }

    private static AuthToken CreateAuthToken(Uri requestUri, string accessToken, Dictionary<string, StringValues> parameters)
    {
        _ = TryGetParameterValue(parameters, "refresh_token", out var refreshToken);
        _ = TryGetParameterValue(parameters, "id_token", out var idToken);

        return new AuthToken
        {
            RequestUri = requestUri,

            AccessToken = accessToken,
            RefreshToken = refreshToken,
            IdToken = idToken,

            TokenType = GetParameterValue(parameters, "token_type"),
            Scope = GetParameterValue(parameters, "scope", string.Empty),
            ExpiresIn = long.Parse(GetParameterValue(parameters, "expires_in", "0")),

            Other = new Dictionary<string, JsonElement>(),
        };
    }

    public static AuthResult CreateError(Uri requestUri, string error, string errorDescription)
    {
        return new AuthError
        {
            RequestUri = requestUri,
            Error = error,
            ErrorDescription = errorDescription
        };
    }

    private static bool TryGetParameterValue(Dictionary<string, StringValues> parameters, string parameterName, [NotNullWhen(true)] out string? value)
    {
        if (parameters.TryGetValue(parameterName, out var values))
        {
            value = values.ToString();
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }
            return true;
        }
        value = null;
        return false;
    }

    private static string GetParameterValue(Dictionary<string, StringValues> parameters, string parameterName)
    {
        if (!parameters.TryGetValue(parameterName, out var values))
        {
            throw new Exception($"Missing required parameter: {parameterName}");
        }
        var value = values.ToString();
        if (value == null)
        {
            throw new Exception($"Missing required parameter: {parameterName}");
        }

        return value;
    }
    private static string GetParameterValue(Dictionary<string, StringValues> parameters, string parameterName, string defaultValue)
    {
        if (!parameters.TryGetValue(parameterName, out var values))
        {
            return defaultValue;
        }
        return values.ToString() ?? defaultValue;
    }
}

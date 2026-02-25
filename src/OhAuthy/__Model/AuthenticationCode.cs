namespace Ww.OhAuthy;

public sealed class AuthenticationCode(
    Uri requestUri,
    string code,
    string state
) : AuthenticationResult(requestUri)
{
    public string Code { get; } = code;

    public string State { get; } = state;
}

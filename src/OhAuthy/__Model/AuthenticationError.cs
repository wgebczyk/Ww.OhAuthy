namespace Ww.OhAuthy;

public sealed class AuthenticationError(Uri requestUri, string error, string errorDescription) : AuthenticationResult(requestUri)
{
    public string Error { get; } = error;
    public string ErrorDescription { get; } = errorDescription;
}

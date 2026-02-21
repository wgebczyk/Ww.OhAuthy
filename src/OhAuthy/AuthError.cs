namespace Ww.OhAuthy;

public sealed class AuthError : AuthResult
{
    public required string Error { get; set; }
    public required string ErrorDescription { get; set; }
}

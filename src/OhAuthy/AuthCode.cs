namespace Ww.OhAuthy;

public sealed class AuthCode : AuthResult
{
    public required string Code { get; set; }
    public string? State { get; set; }
}

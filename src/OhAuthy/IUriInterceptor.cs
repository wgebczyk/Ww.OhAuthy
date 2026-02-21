namespace Ww.OhAuthy;

public interface IUriInterceptor
{
    Task<AuthResult> ListenToSingleRequestAndRespondAsync(
        int port,
        string path,
        Func<AuthResult, string> responseProducer,
        CancellationToken cancellationToken);
}

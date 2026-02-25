namespace Ww.OhAuthy;

public interface IUriInterceptor
{
    Task<AuthenticationResult> ListenToSingleRequestAndRespondAsync(
        int port,
        string path,
        Func<AuthenticationResult, string> responseProducer,
        CancellationToken cancellationToken);
}

using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;

namespace Ww.OhAuthy;

// BASED-ON: https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/main/src/client/Microsoft.Identity.Client/Platforms/Features/DefaultOSBrowser/HttpListenerInterceptor.cs
public sealed class LocalhostHttpListenerInterceptor(ILogger logger) : IUriInterceptor
{
    public async Task<AuthResult> ListenToSingleRequestAndRespondAsync(
        int port,
        string path,
        Func<AuthResult, string> responseProducer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        HttpListener? httpListener = null;
        string urlToListenTo = string.Empty;
        try
        {
            httpListener = new HttpListener();
            httpListener.Prefixes.Add(GetListenerPrefix(port, path));

            httpListener.Start();
            logger.LogInformation("Listening for authorization code on " + urlToListenTo);

            using (cancellationToken.Register(() =>
            {
                logger.LogWarning("HttpListener stopped because cancellation was requested.");
                try { httpListener?.Abort(); }
                catch { }
            }))
            {
                HttpListenerContext context = await httpListener.GetContextAsync().ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                var authorizationResult = await GetAuthorizationResponseAsync(context).ConfigureAwait(false);

                Respond(responseProducer, context, authorizationResult);
                logger.LogTrace("HttpListner received a message on " + urlToListenTo);

                return authorizationResult;
            }
        }
        // If cancellation is requested before GetContextAsync is called, then either
        // an ObjectDisposedException or an HttpListenerException is thrown.
        // But this is just cancellation
        catch (Exception ex) when (ex is HttpListenerException || ex is ObjectDisposedException)
        {
            logger.LogInformation("HttpListenerException - cancellation requested: " + cancellationToken.IsCancellationRequested);
            cancellationToken.ThrowIfCancellationRequested();

            if (ex is HttpListenerException)
            {
                throw new Exception(
                    $"An HttpListenerException occurred while listening on {urlToListenTo} for the system browser to complete the login. " +
                    "Possible cause and mitigation: the app is unable to listen on the specified URL; " +
                    "run 'netsh http add iplisten 127.0.0.1' from the Admin command prompt.",
                    ex);
            }

            // if cancellation was not requested, propagate original ex
            throw;
        }
        finally
        {
            try { httpListener?.Abort(); }
            catch { }
        }
    }

    private static string GetListenerPrefix(int port, string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }
        else
        {
            path = (path.StartsWith("/") ? path : "/" + path);
        }

        var urlToListenTo = "http://localhost:" + port + path;

        if (!urlToListenTo.EndsWith("/"))
        {
            urlToListenTo += "/";
        }

        return urlToListenTo;
    }

    private async Task<AuthResult> GetAuthorizationResponseAsync(HttpListenerContext context)
    {
        var requestMethod = context.Request.HttpMethod;
        var requestUrl = context.Request.Url!;
        logger.LogInformation($"Received {requestMethod} request. HasEntityBody: {context.Request.HasEntityBody}");
        logger.LogTrace($"Request URL: {requestUrl}");

        switch (requestMethod)
        {
            case "GET":
                return AuthResult.FromUri(requestUrl);
            case "POST":
                return await GetAuthorizationResponseFromPostAsync(context.Request).ConfigureAwait(false);
            default:
                logger.LogError($"Unsupported HTTP method: {requestMethod}. Expected GET or POST.");
                throw new NotSupportedException($"Unsupported HTTP method: {requestMethod}. Expected GET or POST.");
        }
    }

    private async Task<AuthResult> GetAuthorizationResponseFromPostAsync(HttpListenerRequest request)
    {
        if (!request.HasEntityBody)
        {
            logger.LogError($"Security violation: Expected POST request with form_post, but received {request.HttpMethod}.");
            throw new Exception($"Expected POST request for form_post response mode, but received {request.HttpMethod}.");
        }

        logger.LogInformation("Processing POST request with entity body (form_post response)");

        using var memoryStream = new MemoryStream();
        await request.InputStream.CopyToAsync(memoryStream).ConfigureAwait(false);
        byte[] postData = memoryStream.ToArray();

        logger.LogInformation($"Received POST data with {postData.Length} bytes");
        logger.LogTrace("Successfully processed POST data");

        return AuthResult.FromPostData(request.Url!, postData);
    }

    private void Respond(Func<AuthResult, string> responseProducer, HttpListenerContext context, AuthResult authorizationResult)
    {
        var message = responseProducer(authorizationResult);
        logger.LogInformation("Processing a response message to the browser. HttpStatus: OK");

        byte[] buffer = Encoding.UTF8.GetBytes(message);
        context.Response.ContentLength64 = buffer.Length;
        context.Response.OutputStream.Write(buffer, 0, buffer.Length);

        context.Response.OutputStream.Close();
    }
}
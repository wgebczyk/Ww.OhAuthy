using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System.Globalization;
using System.Net;

namespace Ww.OhAuthy;

// BASED-ON: https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/main/src/client/Microsoft.Identity.Client/Platforms/Features/DefaultOSBrowser/DefaultOsBrowserWebUi.cs
public sealed class LocalhostBrowserAuthentication
{
    internal const string DefaultSuccessHtml =
    """
    <html>
        <head><title>Authentication Complete</title></head>
        <body>
        <h3>Authentication complete.</h3>
        <p>You can return to the application. Please close this browser tab.</p>
        <p><strong>For your security:</strong> Do not share the contents of this page, the address bar, or take screenshots.</p>
        </body>
    </html>
    """;

    internal const string DefaultFailureHtml =
    """
    <html>
      <head><title>Authentication Failed</title></head>
      <body>
        <h3>Authentication failed.</h3>
        <p>You can return to the application. Please close this browser tab.</p>
        <p><strong>For your security:</strong> Do not share the contents of this page, the address bar, or take screenshots.</p>
        </br>
        <p>Error details: error {0} error_description: {1}</p>
      </body>
    </html>
    """;

    private readonly IUriInterceptor _uriInterceptor;
    private readonly IPlatformProxy _platformProxy;
    private readonly ILogger<LocalhostBrowserAuthentication> _logger;

    public LocalhostBrowserAuthentication(
        IPlatformProxy proxy,
        ILogger<LocalhostBrowserAuthentication> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _platformProxy = proxy ?? throw new ArgumentNullException(nameof(proxy));

        _uriInterceptor = new LocalhostHttpListenerInterceptor(_logger);
    }

    public async Task<AuthResult> AcquireAuthorizationAsync(
        Uri authorizationUri,
        Uri redirectUri,
        CancellationToken cancellationToken)
    {
        try
        {
            // Warn if response_mode was set to something other than form_post
            if (authorizationUri.Query.Contains("response_mode=") &&
                !authorizationUri.Query.Contains("response_mode=form_post"))
            {
                _logger.LogWarning("The 'response_mode' parameter will be overridden to 'form_post' for better security.");
            }

            authorizationUri = new Uri(QueryHelpers.AddQueryString(authorizationUri.OriginalString, "response_mode", "form_post"), UriKind.RelativeOrAbsolute);

            _logger.LogInformation($"Authorization URI with form_post: {authorizationUri.AbsoluteUri}");
            _logger.LogTrace($"Query string contains response_mode: {authorizationUri.Query.Contains("response_mode=form_post")}");

            var authResponse = await InterceptAuthorizationUriAsync(
                authorizationUri,
                redirectUri,
                cancellationToken)
                .ConfigureAwait(true);

            if (!authResponse.RequestUri.Authority.Equals(redirectUri.Authority, StringComparison.OrdinalIgnoreCase) ||
               !authResponse.RequestUri.AbsolutePath.Equals(redirectUri.AbsolutePath))
            {
                throw new Exception(
                    $"[LoopbackResponseUriMismatch] Redirect Uri mismatch. Expected ({authResponse.RequestUri.AbsolutePath}) Actual ({redirectUri.AbsolutePath})."
                );
            }
            _logger.LogInformation("Processing form_post response securely from POST data");
            return authResponse;
        }
        catch (HttpListenerException) // sometimes this exception sneaks out (see issue 1773)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
    }

    public Uri UpdateRedirectUri(Uri redirectUri)
    {
        if (!redirectUri.IsLoopback)
        {
            throw new Exception(
                $"[LoopbackRedirectUri] Only loopback redirect uri is supported, but {redirectUri.AbsoluteUri} was found. Configure http://localhost or http://localhost:port both during app registration and when you create the PublicClientApplication object. See https://aka.ms/msal-net-os-browser for details");
        }

        // AAD does not allow https:\\localhost redirects from any port
        if (redirectUri.Scheme != "http")
        {
            throw new Exception(
                $"[LoopbackRedirectUri] Only http uri scheme is supported, but {redirectUri.Scheme} was found. Configure http://localhost or http://localhost:port both during app registration and when you create the PublicClientApplication object. See https://aka.ms/msal-net-os-browser for details");
        }

        return redirectUri;
    }

    private async Task<AuthResult> InterceptAuthorizationUriAsync(
        Uri authorizationUri,
        Uri redirectUri,
        CancellationToken cancellationToken)
    {
        Func<Uri, Task> defaultBrowserAction = (Uri u) => _platformProxy.StartDefaultOsBrowserAsync(u.AbsoluteUri);

        cancellationToken.ThrowIfCancellationRequested();
        await defaultBrowserAction(authorizationUri).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        return await _uriInterceptor.ListenToSingleRequestAndRespondAsync(
            redirectUri.Port,
            redirectUri.AbsolutePath,
            GetResponseMessage,
            cancellationToken)
        .ConfigureAwait(false);
    }

    private string GetResponseMessage(AuthResult authorizationResult)
    {
        if (authorizationResult is AuthError error)
        {
            _logger.LogWarning($"Default OS Browser intercepted an Uri with an error: {error.Error} {error.ErrorDescription}");

            string errorMessage = string.Format(
                    CultureInfo.InvariantCulture,
                    DefaultFailureHtml,
                    error.Error,
                    error.ErrorDescription);

            return errorMessage;
        }

        return DefaultSuccessHtml;
    }
}

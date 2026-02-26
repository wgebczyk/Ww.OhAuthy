# Ww.OhAuthy

This work is based on the Microsoft Authentication Library (MSAL) for .NET, which is licensed under the MIT License. The original code can be found in the MSAL repository on GitHub.

- [BASED-ON: DefaultOsBrowserWebUi.cs](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/main/src/client/Microsoft.Identity.Client/Platforms/Features/DefaultOSBrowser/DefaultOsBrowserWebUi.cs)
- [BASED-ON: HttpListenerInterceptor.cs](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/main/src/client/Microsoft.Identity.Client/Platforms/Features/DefaultOSBrowser/HttpListenerInterceptor.cs)

## Get token from Auth0

Register Single Page Application in Auth0, setup redirect uri to http://localhost:4200/auth or other you like,
and use the following code to get token.

**NOTE**: I'm not sure if Origin header is required for Auth0.

```
var authCodeSettings = new AuthorizationCodeFlowSettings(
    authorizeUrl: "https://<auth0-subdomain-created-for-you>/authorize",
    clientId: "<client-id-long-semi-random-defined-by-auth0>",
    redirectUrl: "http://localhost:<some-port>/<some-path>",
    scopes: ["openid", "profile", "offline_access"]
);

var res1 = await client.ExecuteAuthorizationCodeFlowAsync(authCodeSettings, ...);
if (!(res1 is AuthenticationCode authCode)) { return; }
Console.WriteLine(authCode.Code);
```

```
var codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
    tokenUrl: https://<auth0-subdomain-created-for-you>/oauth/token,
    authCodeSettings,
    authCode
);

var res2 = await client.ExecuteAuthorizationCodeExchangeTokenFlowAsync(codeExchangeTokenSettings, ...);
if (!(res2 is AuthenticationToken authToken)) { return; }
Console.WriteLine(authToken.AccessToken);
```

```
var tokenRefreshSettings = new TokenRefreshFlowSettings(
    tokenUrl: https://<auth0-subdomain-created-for-you>/oauth/token,
    authCodeSettings,
    authToken
);

var res3 = await client.ExecuteTokenRefreshFlowAsync(tokenRefreshSettings, ...);
if (!(res3 is AuthenticationToken authTokenRefreshed)) { return; }
Console.WriteLine(authTokenRefreshed.AccessToken);
```

## Get token from Entra ID

Register Single Page Application in Entra ID, setup redirect uri to http://localhost:4200/auth or other you like,
and use the following code to get token.

```
var authCodeSettings = new AuthorizationCodeFlowSettings(
    authorizeUrl: "https://login.microsoftonline.com/<tenant-id>>/oauth2/v2.0/authorize",
    clientId: "<client-id-your-guid>",
    redirectUrl: "http://localhost:<some-port>/<some-path>",
    scopes: ["openid", "profile", "offline_access"]
);

var res1 = await client.ExecuteAuthorizationCodeFlowAsync(authCodeSettings, ...);
if (!(res1 is AuthenticationCode authCode)) { return; }
Console.WriteLine(authCode.Code);
```

```
var codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
    tokenUrl: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
    authCodeSettings,
    authCode
){ SendOrigin = true };

var res2 = await client.ExecuteAuthorizationCodeExchangeTokenFlowAsync(codeExchangeTokenSettings, ...);
if (!(res2 is AuthenticationToken authToken)) { return; }
Console.WriteLine(authToken.AccessToken);
```

```
var tokenRefreshSettings = new TokenRefreshFlowSettings(
    tokenUrl: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
    authCodeSettings,
    authToken
){
    RedirectUri = "http://localhost:<some-port>/<some-path>",
    SendOrigin = true,
};

var res3 = await client.ExecuteTokenRefreshFlowAsync(tokenRefreshSettings, ...);
if (!(res3 is AuthenticationToken authTokenRefreshed)) { return; }
Console.WriteLine(authTokenRefreshed.AccessToken);
```

## Get token from Google API using Authorization Code Flow

Register Web Application in Google Cloud / Console, setup redirect uri to http://localhost:4200/auth or other you like,
and use the following code to get token.

**NOTE**: Google API requires Client Secret to be sent in Token Request, even for public clients. This is not recommended by OAuth 2.0 specification, but it's how Google API works. Make sure to keep your Client Secret safe and do not expose it in client-side applications.

```
var authCodeSettings = new AuthorizationCodeFlowSettings(
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    clientId: "<client-id-that-is-veeeery-long-and-createg-for-you-by-google>",
    redirectUrl: "http://localhost:<some-port>/<some-path>",
    scopes: ["openid", "profile"]
);

var res1 = await client.ExecuteAuthorizationCodeFlowAsync(authCodeSettings, ...);
if (!(res1 is AuthenticationCode authCode)) { return; }
Console.WriteLine(authCode.Code);
```

```
var codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
    tokenUrl: "https://oauth2.googleapis.com/token",
    authCodeSettings,
    authCode
){
    ClientSecret = "<client-secret-you-have-created-and-secured>",
    SendOrigin = true
};

var res2 = await client.ExecuteAuthorizationCodeExchangeTokenFlowAsync(codeExchangeTokenSettings, ...);
if (!(res2 is AuthenticationToken authToken)) { return; }
Console.WriteLine(authToken.AccessToken);
```

## Get token from Google API using Implicit Flow

Same as above, but use Implicit Flow to get token directly from Authorize Endpoint. This flow is not recommended by OAuth 2.0 specification, but it's still supported by Google API.

```
var implicitFlowSettings = new ImplicitFlowSettings(
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    clientId: "<client-id-that-is-veeeery-long-and-createg-for-you-by-google>",
    redirectUri: "http://localhost:<some-port>/<some-path>",
    scopes: ["openid", "profile"]
);

var res = await client.ExecuteImplicitFlowAsync(implicitFlowSettings, ...);
if (!(res is AuthenticationToken authToken)) { return; }
Console.WriteLine(authToken.AccessToken);
```

## Get token from Path of Exile

**NOTE**: Path of Exile API requires User-Agent header to be sent in Token requests. Make sure to set it to something that identifies your application, otherwise your requests might be blocked by their API.

**NOTE**: There seems to be used only 3 ports: 49082 OR 49083 OR 49084.

**NOTE**: Please check PoB version and use correct and honot rate limiting.

**NOTE**: Looks like Exiled Exchange 2 is using this same app registration :D

```
var authCodeSettings = new AuthorizationCodeFlowSettings(
    authorizeUrl: "https://www.pathofexile.com/oauth/authorize",
    clientId: "pob",
    redirectUrl: "http://localhost:49082/",
    scopes: ["account:profile", "account:leagues", "account:characters"]
);

var res1 = await authenticationClient.ExecuteAuthorizationCodeFlowAsync(authCodeSettings, ...);
if (!(res1 is AuthenticationCode authCode)) { return; }
Console.WriteLine(authCode.Code);
```

```
var codeExchangeTokenSettings = new AuthorizationCodeExchangeTokenFlowSettings(
    tokenUrl: "https://www.pathofexile.com/oauth/token",
    authCodeSettings,
    authCode
)
{
    SendOrigin = true,
    SendHeaders = new Dictionary<string, string>
    {
        ["User-Agent"] = "Path of Building/<version>"
    },
};

var res2 = await client.ExecuteAuthorizationCodeExchangeTokenFlowAsync(codeExchangeTokenSettings, ...);
if (!(res2 is AuthenticationToken authToken)) { return; }
Console.WriteLine(authToken.AccessToken);
```

```
var tokenRefreshSettings = new TokenRefreshFlowSettings(
    tokenUrl: "https://www.pathofexile.com/oauth/token",
    authCodeSettings,
    authToken
)
{
    RedirectUri = "http://localhost:49082/",
    SendOrigin = true,
    SendHeaders = new Dictionary<string, string>
    {
        ["User-Agent"] = "Path of Building/<version>"
    },
};

var res3 = await client.ExecuteTokenRefreshFlowAsync(tokenRefreshSettings, ...);
if (!(res3 is AuthenticationToken authTokenRefreshed)) { return; }
Console.WriteLine(authTokenRefreshed.AccessToken);
```

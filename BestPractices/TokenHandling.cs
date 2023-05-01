using Microsoft.Identity.Client;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;

namespace BestPractices
{
    public partial class MainWindow : Window
    {
        private DateTime issuedAt = DateTime.MinValue;
        private DateTime expiresAt = DateTime.MinValue;

        private async Task<string> GetToken(TokenType type, string[] scopes, string claimsChallenge = null, bool silent = false, bool forceRefresh = false)
        {
            Stopwatch sw = Stopwatch.StartNew();
            IAccount firstAccount;
            bool usingWAM = true;
            IntPtr myWindow;

            if (silent == false)
            {
                myWindow = new WindowInteropHelper(this).Handle;
            }
            else
            {
                myWindow = new IntPtr(0);
            }

            var accounts = await MSALPublicClientApp.GetAccountsAsync();
            if (accounts.Any())
            {
                firstAccount = accounts.FirstOrDefault();
            }
            else
            {
                switch (Accounts.SelectedIndex)
                {
                    case 0:
                        firstAccount = PublicClientApplication.OperatingSystemAccount;
                        break;

                    case 1:
                        firstAccount = null;
                        break;

                    default:
                        firstAccount = accounts.FirstOrDefault();
                        usingWAM = false;
                        break;
                }
            }

            AuthenticationResult authResult;
            try
            {
                sw.Start();
                authResult = await MSALPublicClientApp.AcquireTokenSilent(scopes, firstAccount)
                    .WithClaims(claimsChallenge)
                    .WithForceRefresh(forceRefresh)
                    .ExecuteAsync()
                    .ConfigureAwait(false);
                logger.Log($"AcquireTokenSilent took {sw.ElapsedMilliseconds} ms");
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilent. 
                // This indicates you need to call AcquireTokenInteractive to acquire a token

                if (silent == true)
                {
                    logger.Log($"Acquire token silent failed and only silent was requested");
                    return null;
                }
                else
                {

                    logger.Log($"MsalUiRequiredException: {ex.Message}");

                    if (usingWAM)
                    {
                        firstAccount = null;
                    }

                    string[] interactiveScopes;
                    string[] extraScopes;
                    if (type == TokenType.ID)
                    {
                        interactiveScopes = new string[] { "openid" };
                        extraScopes = scopes;
                    }
                    else
                    {
                        interactiveScopes = scopes;
                        extraScopes = new string[] { };
                    }

                    try
                    {
                        sw.Restart();
                        authResult = await MSALPublicClientApp.AcquireTokenInteractive(scopes)
                        .WithClaims(claimsChallenge ?? ex.Claims)
                        .WithParentActivityOrWindow(myWindow)
                        .WithAccount(firstAccount)
                        .WithExtraScopesToConsent(extraScopes)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
                        logger.Log($"AcquireTokenInteractive took {sw.ElapsedMilliseconds} ms");
                    }
                    catch (MsalException msalex)
                    {
                        logger.Log("Error Acquiring Token: " + msalex.Message);
                        authResult = null;
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Log("Error Acquiring Token Silently: " + ex.Message);
                return null;
            }

            if (null != authResult)
            {
                ParseTokenResponseInfo(authResult);

                if (type == TokenType.Access)
                {
                    return authResult.AccessToken;
                }
                else
                {
                    // MSAL always adds the 'openid and profile' scope to every token request, so there will always be an ID Token 
                    // but we only want to look at the ID Token if it is the first one we get or if the scope is openid only
                    ParseIDTokenClaims(authResult);
                    return authResult.IdToken;
                }
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Display information contained in the token response
        /// </summary>
        private void ParseTokenResponseInfo(AuthenticationResult authResult)
        {
            sbResponse.Clear();
            if (authResult != null)
            {
                sbResponse.AppendLine(DateTime.Now.ToString());

                logger.Log($"Token Response" +
                    $" Access Token Expires: {authResult.ExpiresOn.ToLocalTime():F}" +
                    $" | Token Source: {authResult.AuthenticationResultMetadata.TokenSource}" +
                    $" | CacheRefreshReason: {authResult.AuthenticationResultMetadata.CacheRefreshReason}" +
                    $" | Correlation Id: {authResult.CorrelationId}"
                    );

                logger.Log($"ID Token: {authResult.IdToken}", LogType.Console);
                logger.Log($"Access Token: {authResult.AccessToken}", LogType.Console);

                string scopes = "";
                sbResponse.AppendLine("Token Scopes:");
                foreach (string scope in authResult.Scopes)
                {
                    sbResponse.AppendLine($"\t {scope}");
                    scopes += $"{scope} ";
                }
                logger.Log($"Scopes in token: {scopes}");

                sbResponse.AppendLine($"Token Expires: {authResult.ExpiresOn.ToLocalTime():F}");
                AccessTokenExpContent = $"Access Token Expires at: {authResult.ExpiresOn.ToLocalTime():F}";

                if (authResult.AuthenticationResultMetadata.RefreshOn != null)
                {
                    sbResponse.AppendLine($"Refresh On: {authResult.AuthenticationResultMetadata.RefreshOn.Value.ToLocalTime():F}");
                }
                sbResponse.AppendLine($"Token Source: {authResult.AuthenticationResultMetadata.TokenSource}");
                sbResponse.AppendLine($"CacheRefreshReason: {authResult.AuthenticationResultMetadata.CacheRefreshReason}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"User name: {authResult.Account.Username}");
                sbResponse.AppendLine($"Home Account Id Identifier: {authResult.Account.HomeAccountId.Identifier}");
                sbResponse.AppendLine($"Home Account Id ObjectId: {authResult.Account.HomeAccountId.ObjectId}");
                sbResponse.AppendLine($"Home Account Id TenantId: {authResult.Account.HomeAccountId.TenantId}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"Cache time: {authResult.AuthenticationResultMetadata.DurationInCacheInMs}");
                sbResponse.AppendLine($"HTTP time: {authResult.AuthenticationResultMetadata.DurationInHttpInMs}");
                sbResponse.AppendLine($"Total time: {authResult.AuthenticationResultMetadata.DurationTotalInMs}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"Tenant Id: {authResult.TenantId}");
                sbResponse.AppendLine($"Unique Id: {authResult.UniqueId}");
                sbResponse.AppendLine($"Environment: {authResult.Account.Environment}");
            }
        }

        private void ParseIDTokenClaims(AuthenticationResult authResult)
        {
            sbIDTokenClaims.Clear();

            userIsSignedIn = true;
            foreach (var claim in authResult.ClaimsPrincipal.Claims)
            {
                string desc = "";
                if (claim.Type == "exp")
                {
                    expiresAt = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                    expiresAt = expiresAt.AddSeconds(Double.Parse(claim.Value)).ToLocalTime();
                    var msToWait = expiresAt.Subtract(DateTime.Now).TotalMilliseconds;
                    if (msToWait < 0)
                    {
                        // MSAL has given us a cached ID Token which has already expired. 
                        logger.Log($"MSAL has given us a cached ID Token which expired {msToWait / 1000 / 60,1:N1} minutes ago.");
                        IDTokenExpContent = $"ID Token Expired {msToWait / 1000 / 60 * -1,1:N1} minutes ago.";
                    }
                    else
                    {
                        logger.Log($"ID expires in {msToWait / 1000 / 60,1:N1} minutes at: {expiresAt}");
                        IDTokenExpContent = $"OIDC ID Token Expires at: {expiresAt:F}";
                    }
                    desc = $" - (in local time: {expiresAt})";
                }
                else if (claim.Type == "nbf" || claim.Type == "iat" || claim.Type == "auth_time" || claim.Type == "pwd_exp")
                {
                    DateTime claimDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                    claimDateTime = claimDateTime.AddSeconds(Double.Parse(claim.Value)).ToLocalTime();
                    desc = $" - (in local time: {claimDateTime})";
                    if (claim.Type == "iat")
                    {
                        issuedAt = claimDateTime.AddMinutes(5);
                    }
                }
                else if (claim.Type == "tid")
                {
                    logger.Log($"Tenant ID is:{claim.Value}");
                }
                sbIDTokenClaims.AppendLine($"\"{claim.Type}\": \"{claim.Value}\"{desc}");
            }
        }

    }
}

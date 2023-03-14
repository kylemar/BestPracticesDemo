using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;

namespace BestPractices
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static IPublicClientApplication _clientApp = null;
        private bool userIsSignedIn = false;
        private readonly System.Timers.Timer reAuthTimer = new System.Timers.Timer();
        private readonly System.Timers.Timer callGraphTimer = new System.Timers.Timer();
        private static readonly StringBuilder sbLog = new StringBuilder();
        private static readonly StringBuilder sbIDTokenClaims = new StringBuilder();
        private static readonly StringBuilder sbResponse = new StringBuilder();
        private static readonly StringBuilder sbResults = new StringBuilder();
        private readonly Logger logger = new Logger(sbLog);

        public MainWindow()
        {
            reAuthTimer.Elapsed += ReAuthUser;
            callGraphTimer.Elapsed += CheckGroupMembership;
            InitializeComponent();
            UpdateScreen();
        }

        /// <summary>
        /// Call Login
        /// </summary>
        private async void SignInButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            LogText.Text = String.Empty;
            logger.Start();
            sbLog.Clear();

            if (_clientApp != null )
            {
                var accounts = await _clientApp.GetAccountsAsync();
                if (accounts.Any())
                {
                    try
                    {
                        await _clientApp.RemoveAsync(accounts.FirstOrDefault());
                        _clientApp = null;
                    }
                    catch (MsalException msalex)
                    {
                        logger.Log("Error signing out user: " + msalex.Message);
                    }
                }
            }

            ComboBoxItem authority = Authority.SelectedItem as ComboBoxItem;
            var builder = PublicClientApplicationBuilder.Create(App.ClientId)
                .WithAuthority(AzureCloudInstance.AzurePublic, authority.Tag as String);

            ComboBoxItem scopes = Scopes.SelectedItem as ComboBoxItem;
            var ScopesString = scopes.Tag as String;
            if (UseCAE.IsChecked == true)
            {
                builder.WithClientCapabilities(new[] { "cp1" });
                callGraphTimer.Interval = 60000;
            }

            ComboBoxItem account = Accounts.SelectedItem as ComboBoxItem;
            var accountType = account.Tag as string;
            if (accountType.Contains("Windows"))
            {
                // builder.WithExperimentalFeatures();
                builder.WithWindowsBroker(true);  
                builder.WithDefaultRedirectUri();
            }
            else
            {
                builder.WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient");
            }

            _clientApp = builder.Build();
            TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);

            string[] scopesRequest = ScopesString.Split(' ');
            try
            {
                await AuthAndCallAPI(null, scopesRequest);
                CheckGroupMembership(null, null);
                callGraphTimer.Start();
            }
            catch (Exception ex)
            {
                logger.Log($"Sign in failed with: {ex.Message}");
            }

            UpdateScreen();
        }

        private async void CallUserInfoButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            //Set the API Endpoint to OIDC UserInfo endpoint (which is hosted in Microsoft Graph)
            string graphAPIEndpoint = "https://graph.microsoft.com/oidc/userinfo";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "openid"};

            try
            {
                string results = await AuthAndCallAPI(graphAPIEndpoint, scopes);
                results = results.Replace(",", "," + Environment.NewLine);
                sbResults.Append(results);
            }
            catch (Exception ex)
            {
                logger.Log($"UserInfo failed with: {ex.Message}");
            }

            UpdateScreen();
        }

        private async void CallProfileButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            //Set the API Endpoint to Graph 'me' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "user.read" };

            try
            {
                string results = await AuthAndCallAPI(graphAPIEndpoint, scopes);
                results = results.Replace(",", "," + Environment.NewLine);
                sbResults.Append(results);
            }
            catch (Exception ex)
            {
                logger.Log($"Profile failed with: {ex.Message}");
            }

            UpdateScreen();

        }

        private async void CallPeopleButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/People";

            string[] scopes = new string[] { "people.read" };

            try
            {
                string results = await AuthAndCallAPI(graphAPIEndpoint, scopes);
                results = results.Replace(",", "," + Environment.NewLine);
                sbResults.Append(results);
            }
            catch (Exception ex)
            {
                logger.Log($"People failed with: {ex.Message}");
            }

            UpdateScreen();
        }

        private async void CallGroupsButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            //Set the API Endpoint to Graph 'Groups' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/groups";
            string[] scopes = new string[] { "group.read.all" };

            try
            {
                string results = await AuthAndCallAPI(graphAPIEndpoint, scopes);
                results = results.Replace(",", "," + Environment.NewLine);
                sbResults.Append(results);
            }
            catch (Exception ex)
            {
                logger.Log($"Groups failed with: {ex.Message}");
            }

            UpdateScreen();
        }

        private async Task<string> AuthAndCallAPI(string APIEndpoint, string[] scopes, bool silent = false, bool forceRefresh = false)
        {
            sbResults.Clear();
            sbResponse.Clear(); 
            sbIDTokenClaims.Clear();
            string results = null;

            var accessToken = await GetAccessToken(scopes, null, silent, forceRefresh);
            if (null != accessToken)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    try
                    {
                        results = await GetHttpContentWithToken(APIEndpoint, accessToken, scopes, !silent);
                    }
                    catch (Exception ex) 
                    { 
                        throw(ex);
                    }
                }
            }
            return results;
        }

        private async Task<string> GetAccessToken(string[] scopes, string claimsChallenge = null, bool silent = false, bool forceRefresh = false )
        {
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

            var accounts = await _clientApp.GetAccountsAsync();
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
                authResult = await _clientApp.AcquireTokenSilent(scopes, firstAccount)
                    .WithClaims(claimsChallenge)
                    .WithForceRefresh(forceRefresh)
                    .ExecuteAsync()
                    .ConfigureAwait(false);
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

                    try
                    {
                        authResult = await _clientApp.AcquireTokenInteractive(scopes)
                        .WithClaims(claimsChallenge ?? ex.Claims)
                        .WithParentActivityOrWindow(myWindow)
                        .WithAccount(firstAccount)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
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
                ParseIDTokenClaims(authResult);
                ParseTokenResponseInfo(authResult);
                return authResult.AccessToken;
            }
            else
            {
                return null;
            }
        }

        private async void ReAuthUser(Object source, ElapsedEventArgs e)
        {
            reAuthTimer.Stop();
            logger.Log($"ReAuthUser");
            string[] scopes = new string[] { "openid" };
            try
            {
                var result = await AuthAndCallAPI(null, scopes, true, true);
                if (result == null)
                {
                    userIsSignedIn = false;
                }
                else
                {
                    userIsSignedIn = true;
                }
            }
            catch (Exception ex)
            {
                userIsSignedIn = false;
                logger.Log(ex.Message);
            }

            UpdateScreen();
        }

        private async void CheckGroupMembership(Object source, ElapsedEventArgs e)
        {
            callGraphTimer.Stop();
            string result = "Group query failed.";
            string message = null;
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "user.read" };

            try
            {
                result = await AuthAndCallAPI(graphAPIEndpoint, scopes,true);
                GroupResults groupResults = JsonSerializer.Deserialize<GroupResults>(result);
                StringBuilder sbGroups = new StringBuilder();
                foreach (Group g in groupResults.value )
                {
                    sbGroups.Append($"{g.id} ");
                }

                logger.Log($"User's group membership:{sbGroups.ToString()}");
                UpdateScreen();
                callGraphTimer.Start();
            }
            catch (Exception ex)
            {
                if (ex.InnerException.Message == "CAEEvent")
                {
                    userIsSignedIn = false;
                    message = "Continous Access Evaluation Event was received. Must sign in again.";
                }
                else
                {
                    logger.Log($"CheckGroupMembership failed with: {ex.Message}");
                }
            }

            UpdateScreen(message);
        }
        /// <summary>
        /// Perform an HTTP GET request to a URL using an HTTP Authorization header
        /// </summary>
        /// <param name="url">The URL</param>
        /// <param name="token">The token</param>
        /// <returns>String containing the results of the GET operation</returns>
        public async Task<string> GetHttpContentWithToken(string url, string token, string [] scopes, bool handleCAE=true)
        {
            Exception innerEx = null;
            string message;

            var httpClient = new HttpClient();
            HttpResponseMessage APIresponse;
            try
            {
                var APIrequest = new HttpRequestMessage(System.Net.Http.HttpMethod.Get, url);
                //Add the token in Authorization header
                APIrequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                APIresponse = await httpClient.SendAsync(APIrequest);

                if (APIresponse.IsSuccessStatusCode)
                {
                    var content = await APIresponse.Content.ReadAsStringAsync();
                    return content;
                }
                else
                {
                    if (APIresponse.StatusCode == System.Net.HttpStatusCode.Unauthorized
                        && APIresponse.Headers.WwwAuthenticate.Any())
                    {
                        AuthenticationHeaderValue bearer = APIresponse.Headers.WwwAuthenticate.First
                            (v => v.Scheme == "Bearer");
                        IEnumerable<string> parameters = bearer.Parameter.Split(',').Select(
                            v => v.Trim()).ToList();
                        var error = GetParameter(parameters, "error");

                        if (null != error && "insufficient_claims" == error)
                        {
                            var claimChallengeParameter = GetParameter(parameters, "claims");
                            if (null != claimChallengeParameter)
                            {
                                var claimChallengebase64Bytes = System.Convert.FromBase64String(
                                    claimChallengeParameter);
                                var ClaimChallenge = System.Text.Encoding.UTF8.GetString(
                                    claimChallengebase64Bytes);

                                logger.Log($"CAE Claims challenge received: {ClaimChallenge}");
                                UpdateScreen();

                                if (handleCAE)
                                {
                                    var newAccessToken = await GetAccessToken(scopes, ClaimChallenge);
                                    if (null != newAccessToken)
                                    {
                                        var APIrequestAfterCAE = new HttpRequestMessage(
                                            System.Net.Http.HttpMethod.Get, url);
                                        APIrequestAfterCAE.Headers.Authorization =
                                            new System.Net.Http.Headers.AuthenticationHeaderValue(
                                                "Bearer", newAccessToken);

                                        HttpResponseMessage APIresponseAfterCAE;
                                        APIresponseAfterCAE = await httpClient.SendAsync(
                                            APIrequestAfterCAE);

                                        if (APIresponseAfterCAE.IsSuccessStatusCode)
                                        {
                                            var content = await APIresponseAfterCAE.Content.ReadAsStringAsync();
                                            var expandedContent = content.Replace(",", "," + Environment.NewLine);
                                            return expandedContent;
                                        }
                                    }
                                }
                                else
                                {
                                    throw new Exception("CAEEvent");
                                }
                            }
                        }
                        message = $"{APIresponse.StatusCode} Authorization token: + {bearer}";
                        logger.Log($"Call to {url} failed with {message}");
                    }
                    message = $"Status:{APIresponse.StatusCode} Reason:{APIresponse.ReasonPhrase} ";
                    string messageToLog = $"Call to {url} failed with {message}";
                    foreach (KeyValuePair<string, IEnumerable<string>> header in APIresponse.Headers)
                    {
                        foreach (string value in header.Value)
                        {
                            messageToLog += $" | {header.Key}: {value}";
                        }
                    }
                    logger.Log(messageToLog);
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
                innerEx = ex;
            }

            throw new Exception($"Call to {url} failed with {message}", innerEx);

        }

        /// <summary>
        /// Sign out the current user
        /// </summary>
        private async void SignOutButton_Click(object sender, RoutedEventArgs e)
        {
            if (_clientApp != null)
            {
                var accounts = await _clientApp.GetAccountsAsync();
                if (accounts.Any())
                {
                    try
                    {                     
                        await _clientApp.RemoveAsync(accounts.FirstOrDefault());
                        this.ResultText.Text = accounts.FirstOrDefault().Username + " User has signed-out";
                        TokenResponseText.Text = string.Empty;
                        IDToken.Text = string.Empty;
                    }
                    catch (MsalException msalex)
                    {
                        logger.Log("Error Acquiring Token: " + msalex.Message);
                    }
                }
                userIsSignedIn = false;
                UpdateScreen();
            }
        }

        /// <summary>
        /// Display basic information contained in the token response
        /// </summary>
        private void ParseTokenResponseInfo(AuthenticationResult authResult)
        {
            sbResponse.Clear();
            if (authResult != null)
            {
                sbResponse.AppendLine(DateTime.Now.ToString());

                logger.Log($"Token Response " +
                    $"| Token Expires: {authResult.ExpiresOn.ToLocalTime()} " +
                    $"| Refresh On: {authResult.AuthenticationResultMetadata.RefreshOn}" +
                    $"| Token Source: {authResult.AuthenticationResultMetadata.TokenSource}" +
                    $"| CacheRefreshReason: {authResult.AuthenticationResultMetadata.CacheRefreshReason}" +
                    $"| Correlation Id: {authResult.CorrelationId} " +
                    $"| ID Token: {authResult.IdToken}" +
                    $"| Access Token: {authResult.AccessToken}"
                    );

                string scopes = "";
                sbResponse.AppendLine("Token Scopes:");
                foreach (string scope in authResult.Scopes)
                {
                    sbResponse.AppendLine($"\t {scope}");
                    scopes += $"{scope} ";
                }
                logger.Log($"Scopes in token: {scopes}");

                sbResponse.AppendLine($"Token Expires: {authResult.ExpiresOn.ToLocalTime()}");
                sbResponse.AppendLine($"Refresh On: {authResult.AuthenticationResultMetadata.RefreshOn}");
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
            // MSAL always adds the 'openid and profile' scope to every token request, so there will always be an ID Token 
            sbIDTokenClaims.Clear();

            userIsSignedIn = true;
            foreach ( var claim in authResult.ClaimsPrincipal.Claims)
            {
                string desc = "";
                if (claim.Type == "exp")
                {
                    DateTime expDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                    expDateTime = expDateTime.AddSeconds(Double.Parse(claim.Value)).ToLocalTime();
                    var msToWait = expDateTime.Subtract(DateTime.Now).TotalMilliseconds;
                    if (msToWait < 0)
                    {
                        // MSAL has given us a cached ID Token which has already expired. 
                        // Reauthenticate the user to the app right away. 
                        logger.Log($"MSAL has given us a cached ID Token which expired {msToWait / 1000 / 60, 1:N1} minuites ago. Reauthenticate the user to the app in 1 minute.");
                        msToWait = 60000;
                    }
                    reAuthTimer.Interval = msToWait;
                    logger.Log($"Set reauth timer to {msToWait / 1000 / 60, 1:N1} minuites. ID Token expires: {expDateTime}");
                    reAuthTimer.Start();
                    desc = $" - (in local time: {expDateTime})";
                }
                else if (claim.Type == "nbf" || claim.Type == "iat" || claim.Type == "auth_time" || claim.Type == "pwd_exp")
                {
                    DateTime claimDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                    claimDateTime = claimDateTime.AddSeconds(Double.Parse(claim.Value)).ToLocalTime();
                    desc = $" - (in local time: {claimDateTime})";
                }
                sbIDTokenClaims.AppendLine($"\"{claim.Type}\": \"{claim.Value}\"{desc}");
            }
        }

        private void Authority_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AccountType != null)
            {
                ComboBoxItem auth = Authority.SelectedItem as ComboBoxItem;
                AccountType.Text = "https://login.microsoftonline.com/oauth/v2.0/" + auth.Tag as String;
            }
        }

        private void Scopes_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SignInScope != null)
            {
                ComboBoxItem scope = Scopes.SelectedItem as ComboBoxItem;
                SignInScope.Text = scope.Tag as String;

                if (SignInScope.Text == "openid")
                {
                    UseCAE.IsChecked = false;
                    UseCAE.IsEnabled = false;
                }
                else
                {
                    UseCAE.IsChecked = true;
                    UseCAE.IsEnabled = true;
                }
            }
        }

        private static string GetParameter(IEnumerable<string> parameters, string parameterName)
        {
            int offset = parameterName.Length + 1;
            return parameters.FirstOrDefault(p => p.StartsWith($"{parameterName}="))?.Substring(offset)?.Trim('"');
        }

        private void UpdateScreen(string message="User is not signed in.")
        {
            Dispatcher.BeginInvoke(new Action(delegate
            {
                LogText.Text = sbLog.ToString();
                LogText.CaretIndex = LogText.Text.Length;
                LogText.ScrollToEnd();

                if (userIsSignedIn)
                {
                    Authority.IsEnabled = false;
                    Accounts.IsEnabled = false;
                    Scopes.IsEnabled = false;
                    SignIn.IsEnabled = false;
                    CallProfileButton.IsEnabled = true;
                    CallPeopleButton.IsEnabled = true;
                    CallGroupsButton.IsEnabled = true;
                    CallUserInfoButton.IsEnabled = true;
                    SignOutButton.IsEnabled = true;
                }
                else
                {
                    callGraphTimer.Stop();
                    Authority.IsEnabled = true;
                    Accounts.IsEnabled = true;
                    Scopes.IsEnabled = true;
                    SignIn.IsEnabled = true;
                    CallProfileButton.IsEnabled = false;
                    CallPeopleButton.IsEnabled = false;
                    CallGroupsButton.IsEnabled = false;
                    CallUserInfoButton.IsEnabled = false;
                    SignOutButton.IsEnabled = false;
                    sbIDTokenClaims.Clear();
                    sbIDTokenClaims.AppendLine(message);
                    sbResponse.Clear();
                    sbResponse.AppendLine(message);
                    sbResults.Clear();
                    sbResults.AppendLine(message);
                }
                ResultText.Text = sbResults.ToString();
                IDToken.Text = sbIDTokenClaims.ToString();
                TokenResponseText.Text = sbResponse.ToString();
            }));
        }
    }
}

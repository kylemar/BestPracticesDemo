using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;

namespace BestPractices
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        [DllImport("user32.dll")]
        private static extern IntPtr GetActiveWindow();

        public IPublicClientApplication _clientApp = null;
        StringBuilder sbLog = new StringBuilder();
        StringBuilder sbIdTokenClaims = new StringBuilder();
        StringBuilder sbResponse = new StringBuilder();
        StringBuilder sbResults = new StringBuilder();

        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Call Login
        /// </summary>
        private async void SignInButton_Click(object sender, RoutedEventArgs e)
        {
            LogText.Text = String.Empty;
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
                        sbLog.AppendLine("Error signing out user: " + msalex.Message);
                    }
                }
            }

            ComboBoxItem authority = Authority.SelectedItem as ComboBoxItem;
            var builder = PublicClientApplicationBuilder.Create(App.ClientId)
                .WithAuthority(AzureCloudInstance.AzurePublic, authority.Tag as String);

            builder.WithClientCapabilities(new[] { "cp1" });

            ComboBoxItem account = Accounts.SelectedItem as ComboBoxItem;
            var accountType = account.Tag as string;
            if (accountType.Contains("Windows"))
            {
                builder.WithExperimentalFeatures();
                builder.WithWindowsBroker(true);  
                builder.WithDefaultRedirectUri();
            }
            else
            {
                builder.WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient");
            }

            _clientApp = builder.Build();
            TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);

            ComboBoxItem scopes = Scopes.SelectedItem as ComboBoxItem;
            var ScopesString = scopes.Tag as String;
            string[] scopesRequest = ScopesString.Split(' ');
            await AuthAndCallAPI(null, scopesRequest);

            UpdateScreen();
        }

        /// <summary>
        /// Call AcquireToken - to acquire a token requiring user to sign-in
        /// </summary>
        private async void CallProfileButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'me' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "user.read" };

            await AuthAndCallAPI(graphAPIEndpoint, scopes);

            UpdateScreen();
        }

        private async void CallPeopleButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/People";

            string[] scopes = new string[] { "people.read" };

            await AuthAndCallAPI(graphAPIEndpoint, scopes);

            UpdateScreen();
        }

        private async void CallGroupsButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'Groups' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/groups";
            string[] scopes = new string[] { "group.read.all" };

            await AuthAndCallAPI(graphAPIEndpoint, scopes);

            UpdateScreen();
        }

        private async Task AuthAndCallAPI(string APIEndpoint, string [] scopes)
        {
            sbResults.Clear();
            sbResponse.Clear(); 
            sbIdTokenClaims.Clear();

            var accessToken = await GetAccessToken(scopes);
            if (null != accessToken)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    var results = await GetHttpContentWithToken(APIEndpoint, accessToken, scopes);
                    sbResults.Append(results);
                }
            }
            return;
        }

        private async Task<string> GetAccessToken(string[] scopes, string claimsChallenge = null )
        {
            IAccount firstAccount;

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
                        break;
                }
            }

            AuthenticationResult authResult = null;
            try
            {
                authResult = await _clientApp.AcquireTokenSilent(scopes, firstAccount)
                    .WithClaims(claimsChallenge)
                    .ExecuteAsync()
                    .ConfigureAwait(false);
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilent. 
                // This indicates you need to call AcquireTokenInteractive to acquire a token
                sbLog.AppendLine($"MsalUiRequiredException: {ex.Message}");

                try
                {
                    authResult = await _clientApp.AcquireTokenInteractive(scopes)
                    .WithClaims(claimsChallenge == null ? claimsChallenge : ex.Claims)
                    .WithParentActivityOrWindow(GetActiveWindow())
                    .WithAccount(firstAccount)
                    .ExecuteAsync()
                    .ConfigureAwait(false);

                    ParseIDTokenClaims(authResult);
                    ParseTokenResponseInfo(authResult);
                }
                catch (MsalException msalex)
                {
                    sbLog.AppendLine("Error Acquiring Token: " + msalex.Message);
                    authResult = null;
                }
            }
            catch (Exception ex)
            {
                sbLog.AppendLine("Error Acquiring Token Silently: " + ex.Message);
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

        /// <summary>
        /// Perform an HTTP GET request to a URL using an HTTP Authorization header
        /// </summary>
        /// <param name="url">The URL</param>
        /// <param name="token">The token</param>
        /// <returns>String containing the results of the GET operation</returns>
        public async Task<string> GetHttpContentWithToken(string url, string token, string [] scopes)
        {
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
                    var expandedContent = content.Replace(",", "," + Environment.NewLine);
                    return expandedContent;
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
                        }
                        return APIresponse.StatusCode.ToString() + " " + "Authorization: " + bearer.ToString();
                    }
                    sbLog.AppendLine(APIresponse.StatusCode + " " + APIresponse.Content.ReadAsStringAsync());
                    return APIresponse.StatusCode.ToString() + " " + APIresponse.ReasonPhrase;
                }
            }
            catch (Exception ex)
            {
                sbLog.AppendLine(ex.Message);
                return null;
            }
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
                        sbLog.AppendLine("Error Acquiring Token: " + msalex.Message);
                    }
                }
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
                sbLog.AppendLine($"Token Response: {DateTime.Now.ToString()}");
                sbLog.AppendLine($"Correlation Id: {authResult.CorrelationId}");
                sbLog.AppendLine("---------------------------------------------------------");


                sbResponse.AppendLine("Token Scopes:");
                foreach (var scope in authResult.Scopes)
                {
                    sbResponse.AppendLine($"\t {scope}");
                }

                sbResponse.AppendLine($"Token Expires: {authResult.ExpiresOn.ToLocalTime()}");
                sbResponse.AppendLine($"Refresh On: {authResult.AuthenticationResultMetadata.RefreshOn}");
                sbResponse.AppendLine($"CacheRefreshReason: {authResult.AuthenticationResultMetadata.CacheRefreshReason}");
                sbResponse.AppendLine($"Cache time: {authResult.AuthenticationResultMetadata.DurationInCacheInMs}");
                sbResponse.AppendLine($"HTTP time: {authResult.AuthenticationResultMetadata.DurationInHttpInMs}");
                sbResponse.AppendLine($"Total time: {authResult.AuthenticationResultMetadata.DurationTotalInMs}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"Correlation Id: {authResult.CorrelationId}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"Tenant Id: {authResult.TenantId}");
                sbResponse.AppendLine($"Unique Id: {authResult.UniqueId}");

                sbResponse.AppendLine($"");
                sbResponse.AppendLine($"User name: {authResult.Account.Username}");
                sbResponse.AppendLine($"Home Account Id Identifier: {authResult.Account.HomeAccountId.Identifier}");
                sbResponse.AppendLine($"Home Account Id ObjectId: {authResult.Account.HomeAccountId.ObjectId}");
                sbResponse.AppendLine($"Home Account Id TenantId: {authResult.Account.HomeAccountId.TenantId}");
                sbResponse.AppendLine($"Environment: {authResult.Account.Environment}");

            }
        }

        private void ParseIDTokenClaims(AuthenticationResult authResult)
        {
            sbIdTokenClaims.Clear();

            foreach ( var claim in authResult.ClaimsPrincipal.Claims)
            {
                sbIdTokenClaims.AppendLine($"\"{claim.Type}\": \"{claim.Value}\"");
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
            }
        }

        private static string GetParameter(IEnumerable<string> parameters, string parameterName)
        {
            int offset = parameterName.Length + 1;
            return parameters.FirstOrDefault(p => p.StartsWith($"{parameterName}="))?.Substring(offset)?.Trim('"');
        }

        private void CheckBox_Checked(object sender, RoutedEventArgs e)
        {
            mainGrid.Background = new SolidColorBrush(System.Windows.Media.Colors.Azure);
        }

        private void CAE_Unchecked(object sender, RoutedEventArgs e)
        {
            mainGrid.Background = new SolidColorBrush(System.Windows.Media.Colors.Red);
        }

        private void UpdateScreen()
        {
            ResultText.Text = sbResults.ToString();
            IDToken.Text = sbIdTokenClaims.ToString();
            TokenResponseText.Text = sbResponse.ToString();
            LogText.Text = sbLog.ToString();
        }
    }
}

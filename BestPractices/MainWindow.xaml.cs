using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace active_directory_wpf_msgraph_v2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public IPublicClientApplication _clientApp = null;

        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Call Login
        /// </summary>
        private async void SignInButton_Click(object sender, RoutedEventArgs e)
        {
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
                        System.Diagnostics.Debug.WriteLine("Error Acquiring Token: " + msalex.Message);
                    }
                }
            }

            ComboBoxItem authority = Authority.SelectedItem as ComboBoxItem;
            _clientApp = PublicClientApplicationBuilder.Create(App.ClientId)
                .WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                .WithAuthority(AzureCloudInstance.AzurePublic, authority.Tag as String)
                .WithClientCapabilities(new [] {"cp1"})
                .Build();
            TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);

            ComboBoxItem scopes = Scopes.SelectedItem as ComboBoxItem;
            var ScopesString = scopes.Tag as String;
            string[] scopesRequest = ScopesString.Split(' ');
            ResultText.Text = await AuthAndCallAPI(null, scopesRequest);
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

            ResultText.Text = await AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private async void CallPeopleButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/People";

            string[] scopes = new string[] { "people.read" };

            ResultText.Text = await AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private async void CallGroupsButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'Groups' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/groups";

            string[] scopes = new string[] { "group.read.all" };

            ResultText.Text = await AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private async Task<string> GetAccessToken(string[] scopes)
        {
            var accounts = await _clientApp.GetAccountsAsync();
            var firstAccount = accounts.FirstOrDefault();
            AuthenticationResult authResult = null;

            try
            {
                authResult = await _clientApp.AcquireTokenSilent(scopes, firstAccount)
                    .ExecuteAsync()
                    .ConfigureAwait(false);
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilent. 
                // This indicates you need to call AcquireTokenInteractive to acquire a token
                System.Diagnostics.Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                try
                {
                    authResult = await _clientApp.AcquireTokenInteractive(scopes)
                        .WithClaims(ex.Claims)
                        .WithAccount(firstAccount)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
                }
                catch (MsalException msalex)
                {
                    System.Diagnostics.Debug.WriteLine("Error Acquiring Token: " + msalex.Message);
                    return null;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Error Acquiring Token Silently: " + ex.Message);
                return null;
            }

            if (null != authResult)
            {
                await Dispatcher.BeginInvoke((Action)( () =>
                {
                    DisplayIDToken(authResult);
                    DisplayBasicTokenResponseInfo(authResult);
                }));

                return authResult.AccessToken;
            }
            else
            {
                return null;
            }
        }

        private async Task<string> GetAccessTokenWithClaimChallenge(string [] scopes, string claimChallenge)
        {
            var accounts = await _clientApp.GetAccountsAsync();
            var firstAccount = accounts.FirstOrDefault();
            AuthenticationResult authResult = null;
            try
            {
                authResult = await _clientApp.AcquireTokenSilent(scopes, firstAccount)
                        .WithClaims(claimChallenge)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
            }
            catch (MsalUiRequiredException)
            {
                try
                {
                    authResult = await _clientApp.AcquireTokenInteractive(scopes)
                        .WithClaims(claimChallenge)
                        .WithAccount(firstAccount)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
                }
                catch (MsalException msalex)
                {
                    System.Diagnostics.Debug.WriteLine("Error Acquiring Token: " + msalex.Message);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
                return null;
            }

            if (authResult != null)
            {
                return authResult.AccessToken;
            }
            return null;
        }

        private async Task<string> AuthAndCallAPI(string APIEndpoint, string [] scopes)
        {
            ResultText.Text = string.Empty;
            TokenResponseText.Text = string.Empty;
            IDToken.Text = string.Empty;

            var accessToken = await GetAccessToken(scopes);
            if (null != accessToken)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    return await GetHttpContentWithToken(APIEndpoint, accessToken, scopes);
                }
            }
            return null;
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
                        IEnumerable<string> parameters = bearer.Parameter.Split(',').Select(v => v.Trim()).ToList();
                        var error = GetParameter(parameters, "error");

                        if (null != error && "insufficient_claims" == error)
                        {
                            var claimChallengeParameter = GetParameter(parameters, "claims");
                            if (null != claimChallengeParameter)
                            {
                                var claimChallengebase64Bytes = System.Convert.FromBase64String(claimChallengeParameter);
                                var ClaimChallenge = System.Text.Encoding.UTF8.GetString(claimChallengebase64Bytes);

                                var newAccessToken = await GetAccessTokenWithClaimChallenge(scopes, ClaimChallenge);
                                if (null != newAccessToken)
                                {
                                    var APIrequestAfterCAE = new HttpRequestMessage(System.Net.Http.HttpMethod.Get, url);
                                    APIrequestAfterCAE.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", newAccessToken);
                                    HttpResponseMessage APIresponseAfterCAE;
                                    APIresponseAfterCAE = await httpClient.SendAsync(APIrequestAfterCAE);

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
                    System.Diagnostics.Debug.WriteLine(APIresponse.StatusCode + " " + APIresponse.Content.ReadAsStringAsync());
                    return APIresponse.StatusCode.ToString() + " " + APIresponse.ReasonPhrase;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
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
                        System.Diagnostics.Debug.WriteLine("Error Acquiring Token: " + msalex.Message);
                    }
                }
            }
        }

        /// <summary>
        /// Display basic information contained in the token response
        /// </summary>
        private void DisplayBasicTokenResponseInfo(AuthenticationResult authResult)
        {
            TokenResponseText.Text = "";
            if (authResult != null)
            {
                TokenResponseText.Text += $"User name: {authResult.Account.Username}" + Environment.NewLine;
                TokenResponseText.Text += $"Home Account Id Identifier: {authResult.Account.HomeAccountId.Identifier}" + Environment.NewLine;
                TokenResponseText.Text += $"Home Account Id ObjectId: {authResult.Account.HomeAccountId.ObjectId}" + Environment.NewLine;
                TokenResponseText.Text += $"Home Account Id TenantId: {authResult.Account.HomeAccountId.TenantId}" + Environment.NewLine;
                TokenResponseText.Text += $"Environment: {authResult.Account.Environment}" + Environment.NewLine;

                TokenResponseText.Text += $"Token Scopes:" + Environment.NewLine;
                foreach (var scope in authResult.Scopes)
                {
                    TokenResponseText.Text += $"\t " + scope + Environment.NewLine;
                }

                TokenResponseText.Text += $"Token Expires: {authResult.ExpiresOn.ToLocalTime()}" + Environment.NewLine;
                TokenResponseText.Text += $"Is Extended LifeTime Token: {authResult.IsExtendedLifeTimeToken.ToString()}" + Environment.NewLine;

                if (authResult.IsExtendedLifeTimeToken)
                {
                    TokenResponseText.Text += $"Extended Expires On: {authResult.ExtendedExpiresOn.ToLocalTime()}" + Environment.NewLine;
                }

                TokenResponseText.Text += $"Correlation Id: {authResult.CorrelationId}" + Environment.NewLine;
                TokenResponseText.Text += $"Tenant Id: {authResult.TenantId}" + Environment.NewLine;
                TokenResponseText.Text += $"Unique Id: {authResult.UniqueId}";
            }
        }

        private void DisplayIDToken(AuthenticationResult authResult)
        {
            IDToken.Text = string.Empty;

            var idtokenHandler = new JwtSecurityTokenHandler();
            if (authResult != null && !string.IsNullOrWhiteSpace(authResult.IdToken)
                && idtokenHandler.CanReadToken(authResult.IdToken))
            {
                var idToken = idtokenHandler.ReadJwtToken(authResult.IdToken);
                var claims = idToken.Claims;
                int handled = 0;
                foreach (var claim in claims)
                {
                    IDToken.Text += "\"" + claim.Type + "\": \"" + claim.Value + "\"";
                    if (++handled < claims.Count())
                    {
                        IDToken.Text += Environment.NewLine;
                    }
                }
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

    }
}

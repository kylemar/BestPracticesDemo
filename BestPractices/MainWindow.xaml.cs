using Microsoft.Identity.Client;
using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;

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
                    catch (MsalException ex)
                    {
                        ResultText.Text = $"Error signing-out user: {ex.Message}";
                    }
                }
            }

            ComboBoxItem authority = Authority.SelectedItem as ComboBoxItem;
            _clientApp = PublicClientApplicationBuilder.Create(App.ClientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, authority.Tag as String)
            .Build();
            TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);

            ComboBoxItem scopes = Scopes.SelectedItem as ComboBoxItem;
            var ScopesString = scopes.Tag as String;
            string[] scopesRequest = ScopesString.Split(' ');
            AuthAndCallAPI(null, scopesRequest);
        }

        /// <summary>
        /// Call AcquireToken - to acquire a token requiring user to sign-in
        /// </summary>
        private void CallProfileButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'me' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "user.read" };

            AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private void CallPeopleButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/People";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "people.read" };

            AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private void CallGroupsButton_Click(object sender, RoutedEventArgs e)
        {
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/groups";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "group.read.all" };

            AuthAndCallAPI(graphAPIEndpoint, scopes);
        }

        private async void AuthAndCallAPI(string APIEndpoint, string [] scopes)
        {
            ResultText.Text = string.Empty;
            TokenResponseText.Text = string.Empty;
            IDToken.Text = string.Empty;

            var accounts = await _clientApp.GetAccountsAsync();
            var firstAccount = accounts.FirstOrDefault();
            AuthenticationResult authResult = null;

            try
            {
                authResult = await _clientApp.AcquireTokenSilent(scopes, firstAccount)
                    .ExecuteAsync();
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilent. 
                // This indicates you need to call AcquireTokenInteractive to acquire a token
                System.Diagnostics.Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                try
                {
                    authResult = await _clientApp.AcquireTokenInteractive(scopes)
                        .WithAccount(firstAccount)
                        .WithParentActivityOrWindow(new WindowInteropHelper(this).Handle) // optional, used to center the browser on the window
                        .WithPrompt(Prompt.SelectAccount)
                        .ExecuteAsync();
                }
                catch (MsalException msalex)
                {
                    ResultText.Text = $"Error Acquiring Token:{System.Environment.NewLine}{msalex}";
                }
            }
            catch (Exception ex)
            {
                ResultText.Text = $"Error Acquiring Token Silently:{System.Environment.NewLine}{ex}";
                return;
            }

            if (authResult != null)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    ResultText.Text = await GetHttpContentWithToken(APIEndpoint, authResult.AccessToken);
                }

                DisplayBasicTokenResponseInfo(authResult);
                DisplayIDToken(authResult);
            }
        }

        /// <summary>
        /// Perform an HTTP GET request to a URL using an HTTP Authorization header
        /// </summary>
        /// <param name="url">The URL</param>
        /// <param name="token">The token</param>
        /// <returns>String containing the results of the GET operation</returns>
        public async Task<string> GetHttpContentWithToken(string url, string token)
        {
            var httpClient = new System.Net.Http.HttpClient();
            System.Net.Http.HttpResponseMessage response;
            try
            {
                var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, url);
                //Add the token in Authorization header
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                response = await httpClient.SendAsync(request);
                var content = await response.Content.ReadAsStringAsync();
                var expandedContent = content.Replace(",", "," + Environment.NewLine);
                return expandedContent;
            }
            catch (Exception ex)
            {
                return ex.ToString();
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
                    catch (MsalException ex)
                    {
                        ResultText.Text = $"Error signing-out user: {ex.Message}";
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
                AccountType.Text = "https://login.microsoftonline.com/" + auth.Tag as String;
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
    }
}

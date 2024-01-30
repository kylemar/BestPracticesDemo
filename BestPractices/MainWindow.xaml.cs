using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace BestPractices
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static IPublicClientApplication MSALPublicClientApp = null;
        private bool userIsSignedIn = false;
        private readonly System.Timers.Timer accessEvaluationTimer = new System.Timers.Timer();

        private static readonly StringBuilder sbLog = new StringBuilder();
        private static readonly StringBuilder sbIDTokenClaims = new StringBuilder();
        private static readonly StringBuilder sbResponse = new StringBuilder();
        private static readonly StringBuilder sbResults = new StringBuilder();
        private static readonly StringBuilder sbRoles = new StringBuilder();

        private readonly Logger logger = new Logger(sbLog);
        private string IDTokenExpContent = "\n\rUser not signed in.";
        private string AccessTokenExpContent = string.Empty;

        private bool doAccessEvaluation = false;
        private bool usingBroker = false;
        private bool usingClaimChallenge = false;
        private bool usingOIDC;
        private bool usingForce = false;

        readonly RolesAndGroupsTabData rolesAndGroupsData = new RolesAndGroupsTabData();
        private bool groupAdmin = false;

        public MainWindow()
        {
            accessEvaluationTimer.Elapsed += AccessEvaluationFunction;
            accessEvaluationTimer.Interval = 60000;

            InitializeComponent();
            
            RolesAndGroupsLV.ItemsSource = rolesAndGroupsData.roleAndGroupMembership;
            UpdateScreen();
        }

        private async void SignInButton_Click(object sender, RoutedEventArgs e)
        {
            Stopwatch sw = Stopwatch.StartNew();
            ResultText.Text = "Working...";
            sbResults.Clear();
            LogText.Text = String.Empty;
            logger.Start();
            sbLog.Clear();

            if (MSALPublicClientApp != null)
            {
                var accounts = await MSALPublicClientApp.GetAccountsAsync();
                if (accounts.Any())
                {
                    try
                    {
                        await MSALPublicClientApp.RemoveAsync(accounts.FirstOrDefault());
                        MSALPublicClientApp = null;
                    }
                    catch (MsalException msalex)
                    {
                        logger.Log("Error signing out user: " + msalex.Message);
                    }
                }
            }

            PublicClientApplicationBuilder builder = PublicClientApplicationBuilder.Create(App.ClientId)
                .WithAuthority(AuthorityAddress.Text);

            if (UseCAE.IsChecked == true)
            {
                builder.WithClientCapabilities(new[] { "cp1" });
            }

            ComboBoxItem account = Accounts.SelectedItem as ComboBoxItem;
            string accountType = account.Tag as string;
            if (accountType.Contains("Windows"))
            {
                BrokerOptions options = new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
                {
                    Title = "Best Practices Demo"
                };
                builder.WithBroker(options);
                builder.WithDefaultRedirectUri();
                usingBroker = true;
            }
            else
            {
                builder.WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient");
                usingBroker = false;
            }

            MSALPublicClientApp = builder.Build();
            TokenCacheHelper.EnableSerialization(MSALPublicClientApp.UserTokenCache);

            string[] scopesRequest = SignInScope.Text.Split(' ');
            try
            {
                _ = await GetToken(TokenType.ID, scopesRequest);
                await AccessEvaluationTask();
                accessEvaluationTimer.Start();
            }
            catch (Exception ex)
            {
                logger.Log($"Sign in failed with: {ex.Message}");
            }

            logger.Log($"Sign in took {sw.ElapsedMilliseconds} ms");
            UpdateScreen();
        }

        private async void CallUserInfoButton_Click(object sender, RoutedEventArgs e)
        {
            if (usingBroker == false)
            {
                ResultText.Text = "Working...";
                sbResults.Clear();

                //Set the API Endpoint to OIDC UserInfo endpoint (which is hosted in Microsoft Graph)
                string graphAPIEndpoint = "https://graph.microsoft.com/oidc/userinfo";

                //Set the scope for API call to openid
                string[] scopes = new string[] { "openid" };

                try
                {
                    string results = await AuthAndGetAPI(graphAPIEndpoint, scopes);
                    if (results != null)
                    {
                        results = results.Replace(",", "," + Environment.NewLine);
                        sbResults.Append(results);
                    }
                    else
                    {
                        sbResults.AppendLine($"Error: No results returned. Check Log");
                    }
                }
                catch (Exception ex)
                {
                    logger.Log($"UserInfo failed with: {ex.Message}");
                }
            }
            else
            {
                sbResults.AppendLine("UserInfo is not available when using the broker");
            }
            UpdateScreen();
        }

        private async void CallProfileButton_Click(object sender, RoutedEventArgs e)
        {
            ResultText.Text = "Working...";
            sbResults.Clear();
            //Set the API Endpoint to Graph 'me' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me";

            //Set the scope for API call to user.read
            string[] scopes = new string[] { "user.read" };

            try
            {
                string results = await AuthAndGetAPI(graphAPIEndpoint, scopes);
                if (results != null)
                {
                    results = results.Replace(",", "," + Environment.NewLine);
                    sbResults.Append(results);
                }
                else
                {
                    sbResults.AppendLine($"Error: No results returned. Check Log");
                }
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
            sbResults.Clear();
            //Set the API Endpoint to Graph 'People' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me/People";

            string[] scopes = new string[] { "people.read" };

            try
            {
                string results = await AuthAndGetAPI(graphAPIEndpoint, scopes);
                if (results != null)
                {
                    results = results.Replace(",", "," + Environment.NewLine);
                    sbResults.Append(results);
                }
                else
                {
                    sbResults.AppendLine($"Error: No results returned. Check Log");
                }
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
            sbResults.Clear();
            //Set the API Endpoint to Graph 'Groups' endpoint
            string graphAPIEndpoint = "https://graph.microsoft.com/v1.0/groups";
            string[] scopes = new string[] { "group.read.all" };

            try
            {
                string results = await AuthAndGetAPI(graphAPIEndpoint, scopes);
                if (results != null)
                {
                    results = results.Replace(",", "," + Environment.NewLine);
                    sbResults.Append(results);
                }
                else
                {
                    sbResults.AppendLine($"Error: No results returned. Check Log");
                }

            }
            catch (Exception ex)
            {
                logger.Log($"Groups failed with: {ex.Message}");
            }

            UpdateScreen();
        }

        /// <summary>
        /// Sign out the current user
        /// </summary>
        private async void SignOutButton_Click(object sender, RoutedEventArgs e)
        {
            if (MSALPublicClientApp != null)
            {
                var accounts = await MSALPublicClientApp.GetAccountsAsync();
                if (accounts.Any())
                {
                    try
                    {
                        await MSALPublicClientApp.RemoveAsync(accounts.FirstOrDefault());
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
                accessEvaluationTimer.Stop();
                UpdateScreen();
            }
        }

        private void Authority_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (AuthorityAddress != null)
            {
                ComboBoxItem auth = Authority.SelectedItem as ComboBoxItem;
                AuthorityAddress.Text = "https://login.microsoftonline.com/" + auth.Tag as String;
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

        private void UpdateScreen(string message = "User is not signed in.")
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
                    ClearTokens.IsEnabled = false;
                    CallProfileButton.IsEnabled = true;
                    CallPeopleButton.IsEnabled = true;
                    UseCAE.IsEnabled = false;
                    if (usingBroker)
                    {
                        CallUserInfoButton.IsEnabled = false;
                    }
                    else
                    {
                        CallUserInfoButton.IsEnabled = true;
                    }
                    if (groupAdmin)
                    {
                        CallGroupsButton.IsEnabled = true;
                    }
                    else
                    {
                        CallGroupsButton.IsEnabled = false;
                    }
                    SignOutButton.IsEnabled = true;
                }
                else
                {
                    issuedAt = DateTime.MinValue;
                    IDTokenExpContent = "\n\rUser not signed in.";
                    AccessTokenExpContent = string.Empty;
                    accessEvaluationTimer.Stop();
                    Authority.IsEnabled = true;
                    Accounts.IsEnabled = true;
                    Scopes.IsEnabled = true;
                    SignIn.IsEnabled = true;
                    UseCAE.IsEnabled = true;
                    ClearTokens.IsEnabled = true;
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


                IDTokenExp.Content = IDTokenExpContent;
                AccessTokenExp.Content = AccessTokenExpContent;
                ResultText.Text = sbResults.ToString();
                IDToken.Text = sbIDTokenClaims.ToString();
                TokenResponseText.Text = sbResponse.ToString();
                RolesText.Text = sbRoles.ToString();
                RolesAndGroupsLV.Items.Refresh();
            }));
        }

        private async void ClearTokens_Click(object sender, RoutedEventArgs e)
        {
            if (MSALPublicClientApp != null)
            {
                var accounts = await MSALPublicClientApp.GetAccountsAsync();
                while (accounts.Any())
                {
                    await MSALPublicClientApp.RemoveAsync(accounts.First());
                    accounts = await MSALPublicClientApp.GetAccountsAsync();
                }
            }
            TokenCacheHelper.ClearCache();
        }

        private void AddRoleOrGroup_Click(object sender, RoutedEventArgs e)
        {
            if (Guid.TryParse(RoleOrGroup.Text, out _))
            {
                RoleAndGroupMemberInfo roleAndGroup = new RoleAndGroupMemberInfo
                {
                    ID = RoleOrGroup.Text,
                    IsMember = "",
                    Name = string.Empty
                };
                rolesAndGroupsData.roleAndGroupMembership.Add(roleAndGroup);
                RolesAndGroupsLV.Height = rolesAndGroupsData.roleAndGroupMembership.Count * 100;
            }
            else 
            {
                System.Windows.MessageBox.Show("Not a valid Role or Group ID", "Best Practices");
            }
        }

        private void AccessEval_Unchecked(object sender, RoutedEventArgs e)
        {
            doAccessEvaluation = false;
        }

        private void AccessEval_Checked(object sender, RoutedEventArgs e)
        {
            doAccessEvaluation = true;
            if (userIsSignedIn)
            {
                _ = AccessEvaluationTask();
            }
        }

        private void ClaimChallenge_Checked(object sender, RoutedEventArgs e)
        {
            usingClaimChallenge = true;
        }

        private void ClaimChallenge_Unchecked(object sender, RoutedEventArgs e)
        {
            usingClaimChallenge = false;
        }

        private void RefreshID_Unchecked(object sender, RoutedEventArgs e)
        {
            usingOIDC = false;
        }

        private void RefreshID_Checked(object sender, RoutedEventArgs e)
        {
            usingOIDC = true;
        }

        private void Force_Unchecked(object sender, RoutedEventArgs e)
        {
            usingForce = false;
        }

        private void Force_Checked(object sender, RoutedEventArgs e)
        {
            usingForce = true;
        }
    }
}

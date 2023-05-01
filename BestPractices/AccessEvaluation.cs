using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System;
using System.Windows;

namespace BestPractices
{
    public partial class MainWindow : Window
    {
        private string ServicePrincipalID = string.Empty;

        private async Task AccessEvaluationTask()
        {
            if (doAccessEvaluation == false)
            {
                return;
            }

            Stopwatch sw = Stopwatch.StartNew();
            sbRoles.Clear();
            accessEvaluationTimer.Stop();
            logger.Log($"AccessEvaluation start");
            string message = null;
            string[] scopes = new string[] { "user.read" };

            try
            {
                string result;
                bool appRoleAssignmentRequired = false;
                List<AppRole> thisAppsAppRoles;

                // Has the ID Token expired? If so, reauthenticate the user
                if (expiresAt <= DateTime.Now)
                {
                    logger.Log($"ReAuth user. ID Token expired at {expiresAt}");
                    try
                    {
                        await GetToken(TokenType.ID, new string[] { "" }, silent: true, forceRefresh: true);
                    }
                    catch (Exception ex)
                    {
                        userIsSignedIn = false;
                        logger.Log(ex.Message);
                        UpdateScreen($"User is not signed in. {ex.Message}");
                        return;
                    }
                }

                //
                // Check for any roles that is app has defined (approles with an allowed member type of users and groups) that have been assigned to this user. 
                // 
                // First step, get the approles for this apps' service principal. This is the entitiy where the approle assignements are made. There is a service principal for this app in every tenant where a user has authenticated to the app
                // Calls to the servicePrincipals endpoint are automatically authorized when an app requests it's own service principal. 
                // We need the SP's ID to query for the approles assigned to this user for this app in this tenant. 
                // While most apps will have hard-coded roles, this app will query for the approles for this SP and check if users must be assigned to the app in order to use the app. 
                //
                if (ServicePrincipalID == string.Empty)
                {
                    string SPsEndpoint = $"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{App.ClientId}')?$select=id";
                    result = await AuthAndGetAPI(SPsEndpoint, scopes, silent: true);
                    ServicePrincipalResults spResults = JsonSerializer.Deserialize<ServicePrincipalResults>(result);
                    if (spResults != null)
                    {
                        ServicePrincipalID = spResults.id;
                    }
                }

                //
                // Get the user's profile from Microsoft Graph. Check:
                // has the user's account be deleted or disabled
                // are the signIn or refresh session valid dates after the current ID Token was issued? 
                // If these any of test fail, consider the user signed out.
                // We should send the user to authenticate. 
                //
                StringBuilder batch = new StringBuilder();
                batch.Append($"{{\"requests\":[");
                batch.Append($"{{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/me?$select=signInSessionsValidFromDateTime,refreshTokensValidFromDateTime,deletedDateTime,accountEnabled\"}},");
                batch.Append($"{{\"id\":\"2\",\"method\":\"GET\",\"url\":\"/servicePrincipals(appId='{App.ClientId}')?$select=id,appRoles,appRoleAssignmentRequired,accountEnabled\",\"dependsOn\":[\"1\"]}},");
                batch.Append($"{{\"id\":\"3\",\"method\":\"GET\",\"url\":\"/me/appRoleAssignments?$filter=resourceId eq {ServicePrincipalID}\",\"dependsOn\":[\"2\"]}}");

                if (rolesAndGroupsData.roleAndGroupMembership.Count > 0)
                {
                    string delimeter = string.Empty;
                    batch.Append($",{{\"id\": \"4\",\"method\": \"POST\",\"url\":\"me/checkMemberObjects\",\"body\":{{\"ids\":[");
                    foreach (RoleAndGroupMemberInfo roleOrGroup in rolesAndGroupsData.roleAndGroupMembership)
                    {
                        string groupstr = $"{delimeter}\"{roleOrGroup.ID}\"";
                        batch.Append(groupstr);
                        delimeter = ",";
                    }
                    batch.Append($"]}},\"headers\":{{\"Content-Type\":\"application/json\"}},\"dependsOn\":[\"3\"]}}");

                }
                batch.Append($"]}}");
                string batchBody = batch.ToString();

                result = await AuthAndPostAPI("https://graph.microsoft.com/v1.0/$batch", scopes, batchBody, silent: true);
                if (result != null)
                {
                    thisAppsAppRoles = new List<AppRole>();
                    BatchResult batchResult = JsonSerializer.Deserialize<BatchResult>(result);
                    foreach (Response r in batchResult.responses)
                    {
                        string bodyJSON = r.body.ToString();
                        switch (r.id)
                        {
                            case "1":
                                UserAccessEvaulationResults uaeResults = JsonSerializer.Deserialize<UserAccessEvaulationResults>(bodyJSON);
                                if (uaeResults != null)
                                {
                                    if (uaeResults.accountEnabled == false)
                                    {
                                        userIsSignedIn = false;
                                        message = "User account disabled. User considered signed out.";
                                        logger.Log(message);
                                        UpdateScreen(message);
                                        return;
                                    }
                                    if (uaeResults.deletedDateTime != null)
                                    {
                                        userIsSignedIn = false;
                                        message = "User account deleted. User considered signed out.";
                                        logger.Log(message);
                                        UpdateScreen(message);
                                        return;
                                    }
                                    if (DateTime.Compare(issuedAt, uaeResults.signInSessionsValidFromDateTime.ToLocalTime()) < 0
                                        || DateTime.Compare(issuedAt, uaeResults.refreshTokensValidFromDateTime.ToLocalTime()) < 0)
                                    {
                                        userIsSignedIn = false;
                                        message = $"ID Token issed at {issuedAt}. User sessions have been revoked at {uaeResults.refreshTokensValidFromDateTime.ToLocalTime()}. User considered signed out.";
                                        logger.Log(message);
                                        UpdateScreen(message);
                                        return;
                                    }
                                }
                                break;

                            case "2":
                                ServicePrincipalResults spResults = JsonSerializer.Deserialize<ServicePrincipalResults>(bodyJSON);
                                if (spResults != null)
                                {
                                    if (spResults.accountEnabled == false)
                                    {
                                        // ServicePrincipal is disabled for authentication. Consider the user signed out
                                        userIsSignedIn = false;
                                        message = $"Enterprise App has been disabled for user authentication. User is considered signed out.";
                                        logger.Log(message);
                                        UpdateScreen(message);
                                        return;
                                    }

                                    if (spResults.appRoles != null)
                                    {
                                        thisAppsAppRoles = spResults.appRoles;
                                    }

                                    appRoleAssignmentRequired = spResults.appRoleAssignmentRequired;
                                }
                                break;

                            case "3":
                                RoleResults roleResults = JsonSerializer.Deserialize<RoleResults>(bodyJSON);
                                if (roleResults.value.Count == 0 && appRoleAssignmentRequired == true)
                                {
                                    // User must be assigned to the app and this user is not assigned (There are no role assignments for this user)
                                    // The user must have signed into the app before the app required assignment. 
                                    // Sign out the user. 
                                    userIsSignedIn = false;
                                    message = $"User assignment required and the user is not assigned. User is considered signed out.";
                                    logger.Log(message);
                                    UpdateScreen(message);
                                    return;
                                }
                                else
                                {
                                    bool found = false;
                                    foreach (Role role in roleResults.value)
                                    {
                                        // the app zeros and dashes Role ID means the user is assigned and has the default role. 
                                        if (role.appRoleId == "00000000-0000-0000-0000-000000000000")
                                        {
                                            sbRoles.AppendLine($"Default Access ");
                                        }
                                        else
                                        {
                                            // 
                                            foreach (AppRole appRole in thisAppsAppRoles)
                                            {
                                                if (appRole.id == role.appRoleId)
                                                {
                                                    sbRoles.AppendLine($"{appRole.displayName} ");
                                                    found = true;
                                                    break;
                                                }
                                            }
                                            if (!found)
                                            {
                                                sbRoles.AppendLine($"Unknown:{role.appRoleId} ");
                                            }
                                        }
                                    }
                                }
                                break;

                            case "4":
                                groupAdmin = false;
                                foreach (RoleAndGroupMemberInfo roleOrGroup in rolesAndGroupsData.roleAndGroupMembership)
                                {
                                    roleOrGroup.IsMember = "No";
                                }

                                GroupResults groupResults = JsonSerializer.Deserialize<GroupResults>(bodyJSON);
                                if (groupResults != null)
                                {
                                    foreach (string groupID  in groupResults.value)
                                    {
                                        foreach (RoleAndGroupMemberInfo roleOrGroup in rolesAndGroupsData.roleAndGroupMembership)
                                        {
                                            if (roleOrGroup.ID == groupID)
                                            {
                                                roleOrGroup.IsMember = "Yes";
                                            }
                                        }
                                        if (groupID == "fdd7a751-b60b-444a-984c-02652fe8fa1c")
                                        {
                                            groupAdmin = true;
                                        }
                                    }
                                }
                                break;
                        }
                    }
                }
                accessEvaluationTimer.Start();
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null && ex.InnerException.Message != null && ex.InnerException.Message == "CAEEvent")
                {
                    userIsSignedIn = false;
                    message = "Continous Access Evaluation Event was received. Must sign in again.";
                }
                else
                {
                    message = $"AccessEvaluation failed with: {ex.Message}";
                    logger.Log(message);
                }
            }

            logger.Log($"Access Evaluation took {sw.ElapsedMilliseconds} ms");
            UpdateScreen(message);
        }

        private async void AccessEvaluationFunction(Object source, ElapsedEventArgs e)
        {
            await AccessEvaluationTask();
        }
    }
}

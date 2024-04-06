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
            string message = null;
            string[] scopes = new string[] { "user.read" };
            Stopwatch sw = Stopwatch.StartNew();
            List<AppRole> thisAppsAppRoles = null;

            try
            {
                string result;
                bool appRoleAssignmentRequired = false;

                // Has the ID Token expired? If so, reauthenticate the user
                // forceRefresh tells MSAL to get a new token. MSAL by default will cache the ID Token based on the Access Token's lifetime
                // Using an NBF claims challenge forces the broker to acquire a new ID Token
                if (usingOIDC && expiresAt <= DateTime.Now)
                {
                    logger.Log($"ReAuth user. ID Token expired at {expiresAt}");
                    try
                    {
                        bool force = false;
                        if (usingForce)
                        {
                            force = true;
                        }
                        await GetToken(TokenType.ID, new string[] { "" }, silent: true, forceRefresh: force);

                    }
                    catch (Exception ex)
                    {
                        userIsSignedIn = false;
                        logger.Log(ex.Message);
                        UpdateScreen($"User is not signed in. {ex.Message}");
                        return;
                    }
                }

                // Doing access evaluation with Microsoft Graph is optional 
                if (doAccessEvaluation == false)
                {
                    UpdateScreen();
                    return;
                }

                logger.Log($"AccessEvaluation start");

                // None of the values we need to do an access evaluation are avalible for users with Microsoft consumer accounts (outlook.com, hotmail.com, xbox.com, skype.com, ....
                if (tenantID != "9188040d-6c67-4c5b-b112-36a304b66dad")
                {
                    // We need the current Service Principal for this app so that we can query the Service Principal for assigned roles 
                    // the format of the call to /servicePrincipals below /servicePrincipals(appId='{App.ClientId}') allows us to access a Service Principal in a different tenant 
                    // this is needed since this is a multi-tenant app
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

                    // We are going to use Microsoft Graph to evaluate if the user should still have access to the app
                    // Doing this check with Microsoft Graph, instead of using claims in the ID Token means the evaulation is up to the moment accurate
                    // Claims in the ID Token could be up to 60 minutes out of date as MSAL will cache the token for it's lifetime
                    // 
                    // For all the calls to Microsoft Graph we need, only user.read is required. 
                    //
                    // Checks
                    //      From the user's profile (/me):
                    //          Has the user's account been disabled or deleted?
                    //          Has our ID Token been issued before the time for signInSessionsValidFromDateTime,refreshTokensValidFromDateTime?
                    //
                    //      From the Service Principal for this app in this tenant
                    //          What are the approles for this app? Most of the time you will not need these but for this app, it lets us get the approle names 
                    //              getting approles names in real time allow the demo to work for app roles defined as the app runs. 
                    //          Is app assignment require for this app? 
                    //          Is the app disabled to sign in users? 
                    //          
                    //      From the user's app roles assignments for this Service Principal (this app)
                    //          If the Service Principal requires assignment and there no assigned roles, consider the user signed out. 
                    //          Gather, and display, the user's role assignments to this app. 
                    //
                    //      From the user's member objects
                    //          Get the list of Azure AD roles and groups for which the user is a member
                    //          which are on our list of Azure AD roles and groups for which we want to know if the user is a member 
                    //          If the user is assigned the Group Administrator role, 

                    StringBuilder batch = new StringBuilder();
                    batch.Append($"{{\"requests\":[");
                    batch.Append($"{{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/me?$select=signInSessionsValidFromDateTime,refreshTokensValidFromDateTime,deletedDateTime,accountEnabled\"}},");
                    batch.Append($"{{\"id\":\"2\",\"dependsOn\": [ \"1\" ],\"method\":\"GET\",\"url\":\"/servicePrincipals(appId='{App.ClientId}')?$select=appRoles,appRoleAssignmentRequired,accountEnabled\"}},");
                    batch.Append($"{{\"id\":\"3\",\"dependsOn\": [ \"2\" ],\"method\":\"GET\",\"url\":\"/me/appRoleAssignments?$filter=resourceId eq {ServicePrincipalID}\"}}");

                    batch.Append($",{{\"id\":\"4\",\"dependsOn\": [ \"3\" ],\"method\": \"POST\",\"url\":\"me/checkMemberObjects\",\"body\":{{\"ids\":[");
                    string delimeter = string.Empty;
                    foreach (RoleAndGroupMemberInfo roleOrGroup in rolesAndGroupsData.roleAndGroupMembership)
                    {
                        string groupstr = $"{delimeter}\"{roleOrGroup.ID}\"";
                        batch.Append(groupstr);
                        delimeter = ",";
                    }
                    batch.Append($"]}},\"headers\":{{\"Content-Type\":\"application/json\"}}}}");

                    batch.Append($"]}}");
                    string batchBody = batch.ToString();

                    result = await AuthAndPostAPI("https://graph.microsoft.com/v1.0/$batch", scopes, batchBody, silent: true);
                    if (result != null)
                    {
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
                                        else
                                        {
                                            thisAppsAppRoles = null;
                                        }

                                        appRoleAssignmentRequired = spResults.appRoleAssignmentRequired;
                                    }
                                    break;

                                case "3":
                                    sbRoles.Clear();
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
                                                if (thisAppsAppRoles != null)
                                                {
                                                    foreach (AppRole appRole in thisAppsAppRoles)
                                                    {
                                                        if (appRole.id == role.appRoleId)
                                                        {
                                                            sbRoles.AppendLine($"{appRole.displayName} ");
                                                            found = true;
                                                            break;
                                                        }
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
                                        foreach (string groupID in groupResults.value)
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
                }
                else
                {
                    logger.Log("No evaluation possible for Microsoft consumer accounts");
                }
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

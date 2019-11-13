using Microsoft.Identity.Client;
using System.Windows;

namespace active_directory_wpf_msgraph_v2
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        static App()
        {
        }

        // Below are the clientId (Application Id) of your app registration and the tenant information. 
        // You have to replace:
        // - the content of ClientID with the Application Id for your app registration
        public static string ClientId = "829f3a28-9104-45e7-a180-a319312bd8c5";

        // - The content of Tenant by the information about the accounts allowed to sign-in 
        //  in your application:
        //   - For Work or School account in your org, use your tenant ID, or domain
        //   - for any Work or School accounts, use organizations
        //   - for any Work or School accounts, or Microsoft personal account, use common
        //   - for Microsoft Personal account, use consumers

        //private static string Tenant = "common";
        //private static string Tenant = "organizations";
        //private static string Tenant = "consumers";
        //private static string Tenant = "c72a295d-d7a5-41ea-a351-b15dd9f67215";

        // private static IPublicClientApplication _clientApp ;

    }
}

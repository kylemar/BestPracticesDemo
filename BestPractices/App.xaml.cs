using Microsoft.Identity.Client;
using System.Windows;

namespace BestPractices
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
        public static string ClientId = "f8a9ff7f-847b-4823-88bf-d2c9061330f7";
    }
}

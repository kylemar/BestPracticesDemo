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
        public static string ClientId = "182a4f96-9d7f-4fc7-a387-dd68c15e52d2";
    }
}

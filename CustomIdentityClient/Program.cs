using System;

namespace CustomIdentityClient
{
    class Program
    {
        static void Main(string[] args)
        {
            var oauth = new OktaOAuth2
            {
                clientID = "test",
                clientSecret = "abcd1234",
                authorizationEndpoint = "https://localhost:5001/api/connect/authorize",
                tokenEndpoint = "https://localhost:5001/api/connect/token",
                userInfoEndpoint = "https://localhost:5001/api/connect/userinfo",
            };

            oauth.doOAuth();

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey(true);
        }
    }
}

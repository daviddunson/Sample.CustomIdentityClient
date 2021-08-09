// Copyright 2020 Okta Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

public class OktaOAuth2
{
    public string authorizationEndpoint;

    // client configuration
    public string clientID;
    public string clientSecret;
    public string tokenEndpoint;
    public string userInfoEndpoint;

    // Start is called before the first frame update
    private void Start()
    {
        doOAuth();
    }

    // ref http://stackoverflow.com/a/3978040
    public static int GetRandomUnusedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint) listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async void doOAuth()
    {
        // Generates state and PKCE values.
        var state = randomDataBase64url(32);
        var code_verifier = randomDataBase64url(32);
        var code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
        const string code_challenge_method = "S256";

        // Creates a redirect URI using an available port on the loopback address.
        var redirectURI = $"http://{IPAddress.Loopback}:{GetRandomUnusedPort()}/";
        output("redirect URI: " + redirectURI);

        // Creates an HttpListener to listen for requests on that redirect URI.
        var http = new HttpListener();
        http.Prefixes.Add(redirectURI);
        output("Listening..");
        http.Start();

        // Creates the OAuth 2.0 authorization request.
        var authorizationRequest =
            $"{authorizationEndpoint}?response_type=code&scope=openid%20profile%20webapi&redirect_uri={Uri.EscapeDataString(redirectURI)}&client_id={clientID}&state={state}&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}";

        // Opens request in the browser.
        Process.Start(new ProcessStartInfo(authorizationRequest) {UseShellExecute = true});

        // Waits for the OAuth authorization response.
        var context = await http.GetContextAsync();

        // Brings the Console to Focus.
        BringConsoleToFront();

        // Sends an HTTP response to the browser.
        var response = context.Response;
        var responseString =
            "<html><head><meta http-equiv='refresh' content='10;url=https://developer.okta.com'></head><body>Please return to the app.</body></html>";
        var buffer = Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        var responseOutput = response.OutputStream;
        var responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith(task =>
        {
            responseOutput.Close();
            http.Stop();
            Console.WriteLine("HTTP server stopped.");
        });

        // Checks for errors.
        if (context.Request.QueryString.Get("error") != null)
        {
            output(string.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
            return;
        }

        if (context.Request.QueryString.Get("code") == null
            || context.Request.QueryString.Get("state") == null)
        {
            output("Malformed authorization response. " + context.Request.QueryString);
            return;
        }

        // extracts the code
        var code = context.Request.QueryString.Get("code");
        var incoming_state = context.Request.QueryString.Get("state");

        // Compares the receieved state to the expected value, to ensure that
        // this app made the request which resulted in authorization.
        if (incoming_state != state)
        {
            output(string.Format("Received request with invalid state ({0})", incoming_state));
            return;
        }

        Console.WriteLine();
        output("Authorization code: " + code);
        Console.WriteLine();

        // Starts the code exchange at the Token Endpoint.
        performCodeExchange(code, code_verifier, redirectURI);
    }

    private async void performCodeExchange(string code, string code_verifier, string redirectURI)
    {
        output("Exchanging code for tokens...");

        // builds the  request
        var tokenRequestBody = string.Format(
            "code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
            code,
            Uri.EscapeDataString(redirectURI),
            clientID,
            code_verifier,
            clientSecret
        );

        // sends the request
        var tokenRequest = (HttpWebRequest) WebRequest.Create(tokenEndpoint);
        tokenRequest.Method = "POST";
        tokenRequest.ContentType = "application/x-www-form-urlencoded";
        //tokenRequest.Accept = "Accept=application/json;charset=UTF-8";
        var _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
        tokenRequest.ContentLength = _byteVersion.Length;
        var stream = tokenRequest.GetRequestStream();
        await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
        stream.Close();

        try
        {
            // gets the response
            var tokenResponse = await tokenRequest.GetResponseAsync();
            using (var reader = new StreamReader(tokenResponse.GetResponseStream()))
            {
                // reads response body
                var responseText = await reader.ReadToEndAsync();
                Console.WriteLine(responseText);

                // converts to dictionary
                var tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                var access_token = tokenEndpointDecoded["access_token"];

                var handler = new JwtSecurityTokenHandler();

                Console.WriteLine();
                Console.WriteLine($"Access Token: {access_token}");
                Console.WriteLine();
                foreach (var claim in handler.ReadJwtToken(access_token).Claims) Console.WriteLine(claim);
                Console.WriteLine();

                var id_token = tokenEndpointDecoded["id_token"];

                Console.WriteLine();
                Console.WriteLine($"ID Token: {id_token}");
                Console.WriteLine();
                foreach (var claim in handler.ReadJwtToken(id_token).Claims) Console.WriteLine(claim);
                Console.WriteLine();

                userinfoCall(access_token);
            }
        }
        catch (WebException ex)
        {
            if (ex.Status == WebExceptionStatus.ProtocolError)
            {
                var response = ex.Response as HttpWebResponse;
                if (response != null)
                {
                    output("HTTP: " + response.StatusCode);
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        // reads response body
                        var responseText = await reader.ReadToEndAsync();
                        output(responseText);
                    }
                }
            }
        }
    }

    private async void userinfoCall(string access_token)
    {
        output("Making API Call to Userinfo...");

        // sends the request
        var userinfoRequest = (HttpWebRequest) WebRequest.Create(userInfoEndpoint);
        userinfoRequest.Method = "GET";
        userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
        userinfoRequest.ContentType = "application/x-www-form-urlencoded";
        //userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

        // gets the response
        var userinfoResponse = await userinfoRequest.GetResponseAsync();
        using (var userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
        {
            // reads response body
            var userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();

            Console.WriteLine();
            output(userinfoResponseText);
            Console.WriteLine();
        }
    }

    /// <summary>
    ///     Appends the given string to the on-screen log, and the debug console.
    /// </summary>
    /// <param name="output">string to be appended</param>
    public void output(string output)
    {
        Console.WriteLine(output);
        Debug.WriteLine(output);
    }

    /// <summary>
    ///     Returns URI-safe data with a given input length.
    /// </summary>
    /// <param name="length">Input length (nb. output will be longer)</param>
    /// <returns></returns>
    public static string randomDataBase64url(uint length)
    {
        var rng = new RNGCryptoServiceProvider();
        var bytes = new byte[length];
        rng.GetBytes(bytes);
        return base64urlencodeNoPadding(bytes);
    }

    /// <summary>
    ///     Returns the SHA256 hash of the input string.
    /// </summary>
    /// <param name="inputStirng"></param>
    /// <returns></returns>
    public static byte[] sha256(string inputStirng)
    {
        var bytes = Encoding.ASCII.GetBytes(inputStirng);
        var sha256 = new SHA256Managed();
        return sha256.ComputeHash(bytes);
    }

    /// <summary>
    ///     Base64url no-padding encodes the given input buffer.
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static string base64urlencodeNoPadding(byte[] buffer)
    {
        var base64 = Convert.ToBase64String(buffer);

        // Converts base64 to base64url.
        base64 = base64.Replace("+", "-");
        base64 = base64.Replace("/", "_");
        // Strips padding.
        base64 = base64.Replace("=", "");

        return base64;
    }

    // Hack to bring the Console window to front.
    // ref: http://stackoverflow.com/a/12066376

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    public void BringConsoleToFront()
    {
        SetForegroundWindow(GetConsoleWindow());
    }
}
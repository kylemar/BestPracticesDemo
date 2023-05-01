using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace BestPractices
{
    public partial class MainWindow : Window
    {
        private async Task<string> AuthAndPostAPI(string APIEndpoint, string[] scopes, string body, bool silent = false, bool forceRefresh = false)
        {
            sbResponse.Clear();
            string results = null;
            string message = "AuthAndPostAPI [";
            foreach (string s in scopes)
            {
                message += $"{s} ";
            }
            message += $"] {APIEndpoint}";
            logger.Log(message);

            var accessToken = await GetToken(TokenType.Access, scopes, null, silent, forceRefresh);
            if (null != accessToken)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    try
                    {
                        results = await PostHttpContentWithToken(APIEndpoint, accessToken, scopes, body, handleCAE: !silent);
                    }
                    catch (Exception ex)
                    {
                        throw (ex);
                    }
                }
            }
            return results;
        }

        private async Task<string> AuthAndGetAPI(string APIEndpoint, string[] scopes, bool silent = false, bool forceRefresh = false)
        {
            sbResponse.Clear();
            string results = null;
            string message = "AuthAndGetAPI [";
            foreach (string s in scopes)
            {
                message += $"{s} ";
            }
            message += $"] {APIEndpoint}";
            logger.Log(message);

            var accessToken = await GetToken(TokenType.Access, scopes, null, silent, forceRefresh);
            if (null != accessToken)
            {
                if (!string.IsNullOrEmpty(APIEndpoint))
                {
                    try
                    {
                        results = await GetHttpContentWithToken(APIEndpoint, accessToken, scopes, !silent);
                    }
                    catch (Exception ex)
                    {
                        throw (ex);
                    }
                }
            }
            return results;
        }

        /// <summary>
        /// Perform an HTTP GET request to a URL using an HTTP Authorization header
        /// </summary>
        /// <param name="url">The URL</param>
        /// <param name="token">The token</param>
        /// <returns>String containing the results of the GET operation</returns>
        public async Task<string> GetHttpContentWithToken(string url, string token, string[] scopes, bool handleCAE = true)
        {
            return await HttpContentWithToken(HttpMethod.Get, url, token, scopes, handleCAE, null);
        }

        public async Task<string> PostHttpContentWithToken(string url, string token, string[] scopes, string body, bool handleCAE = true)
        {
            return await HttpContentWithToken(HttpMethod.Post, url, token, scopes, handleCAE, body);
        }

        static readonly HttpClient httpClient = new HttpClient();

        public async Task<string> HttpContentWithToken(HttpMethod method, string url, string token, string[] scopes, bool handleCAE, string body)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Exception innerEx = null;
            string message;

            //Add the token in Authorization header
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            HttpResponseMessage APIresponse;
            try
            {
                if (method == HttpMethod.Post)
                {
                    var content = new StringContent(body, Encoding.UTF8, "application/json");
                    APIresponse = await httpClient.PostAsync(url, content);
                }
                else if (method == HttpMethod.Get)
                {
                    HttpRequestMessage APIrequest = new HttpRequestMessage(method, url);
                    APIresponse = await httpClient.SendAsync(APIrequest);
                }
                else
                {
                    return null;
                }

                if (APIresponse.IsSuccessStatusCode)
                {
                    string content = await APIresponse.Content.ReadAsStringAsync();
                    logger.Log($"Successful Graph call took {sw.ElapsedMilliseconds} ms");
                    return content;
                }
                else
                {
                    if (APIresponse.StatusCode == System.Net.HttpStatusCode.Unauthorized
                        && APIresponse.Headers.WwwAuthenticate.Any())
                    {
                        AuthenticationHeaderValue bearer = APIresponse.Headers.WwwAuthenticate.First
                            (v => v.Scheme == "Bearer");
                        IEnumerable<string> parameters = bearer.Parameter.Split(',').Select(
                            v => v.Trim()).ToList();
                        var error = GetParameter(parameters, "error");

                        if (null != error && "insufficient_claims" == error)
                        {
                            var claimChallengeParameter = GetParameter(parameters, "claims");
                            if (null != claimChallengeParameter)
                            {
                                var claimChallengebase64Bytes = System.Convert.FromBase64String(
                                    claimChallengeParameter);
                                var ClaimChallenge = System.Text.Encoding.UTF8.GetString(
                                    claimChallengebase64Bytes);

                                logger.Log($"CAE Claims challenge received: {ClaimChallenge}");
                                UpdateScreen();

                                if (handleCAE)
                                {
                                    var newAccessToken = await GetToken(TokenType.Access, scopes, ClaimChallenge);
                                    if (null != newAccessToken)
                                    {
                                        var APIrequestAfterCAE = new HttpRequestMessage(
                                            System.Net.Http.HttpMethod.Get, url);
                                        APIrequestAfterCAE.Headers.Authorization =
                                            new System.Net.Http.Headers.AuthenticationHeaderValue(
                                                "Bearer", newAccessToken);

                                        HttpResponseMessage APIresponseAfterCAE;
                                        APIresponseAfterCAE = await httpClient.SendAsync(
                                            APIrequestAfterCAE);

                                        if (APIresponseAfterCAE.IsSuccessStatusCode)
                                        {
                                            var content = await APIresponseAfterCAE.Content.ReadAsStringAsync();
                                            var expandedContent = content.Replace(",", "," + Environment.NewLine);
                                            return expandedContent;
                                        }
                                    }
                                }
                                else
                                {
                                    throw new Exception("CAEEvent");
                                }
                            }
                        }
                        message = $"{APIresponse.StatusCode} Authorization token: + {bearer}";
                        logger.Log($"Call to {url} failed with {message}");
                    }
                    message = $"Status:{APIresponse.StatusCode} Reason:{APIresponse.ReasonPhrase} ";
                    string messageToLog = $"Call to {url} failed with {message}";
                    foreach (KeyValuePair<string, IEnumerable<string>> header in APIresponse.Headers)
                    {
                        foreach (string value in header.Value)
                        {
                            messageToLog += $" | {header.Key}: {value}";
                        }
                    }
                    logger.Log(messageToLog);
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
                innerEx = ex;
            }
            throw new Exception($"Call to {url} failed with {message}", innerEx);
        }

    }
}

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(AspNetWebApplication.Startup))]

namespace AspNetWebApplication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //Microsoft.Owin.Security.Cookies
            //Microsoft.Owin.Security.OpenIdConnect
            //IdentityModel


            //avoids the renaming of 'sub' claim by MS
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "oidc",
                ClientId = "AspNetWebApplication",
                Authority = "https://localhost:44337/",
                RedirectUri = "https://localhost:44378/",
                Scope = "openid profile email api1",

                SignInAsAuthenticationType = "Cookies",

                PostLogoutRedirectUri = "https://localhost:44378/",

                RequireHttpsMetadata = false,
                UseTokenLifetime = false,

                RedeemCode = true,
                SaveTokens = true,
                ClientSecret = "secret",

                ResponseType = "code",
                ResponseMode = "query",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            // set PKCE parameters
                            var codeVerifier = CryptoRandom.CreateUniqueId(32);

                            string codeChallenge;
                            using (var sha256 = SHA256.Create())
                            {
                                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                                codeChallenge = Base64Url.Encode(challengeBytes);
                            }

                            n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                            n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                            // remember code_verifier (adapted from OWIN nonce cookie)
                            RememberCodeVerifier(n, codeVerifier);
                        }

                        // if signing out, add the id_token_hint
                        else if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenHint != null)
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                        }

                        return Task.CompletedTask;
                    },

                    AuthorizationCodeReceived = n =>
                    {
                        // get code_verifier
                        var codeVerifier = RetrieveCodeVerifier(n);

                        // attach code_verifier
                        n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                        var id = n.OwinContext.Authentication.User;

                        return Task.CompletedTask;
                    },

                    SecurityTokenValidated = async n =>
                    {
                        var id = n.AuthenticationTicket.Identity;                       

                        using (var client = new HttpClient())
                        {
                            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:44337/");
                            var response = await client.GetUserInfoAsync(new UserInfoRequest
                            {
                                Address = disco.UserInfoEndpoint,
                                Token = n.ProtocolMessage.AccessToken
                            });
                            id.AddClaims(response.Claims.Where(x => x.Type != "sub"));
                        }

                        id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        id.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));
                        //n.AuthenticationTicket = new AuthenticationTicket(id, n.AuthenticationTicket.Properties);
                    }
                }
            });
        }

        private void RememberCodeVerifier(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            var properties = new AuthenticationProperties();
            properties.Dictionary.Add("cv", codeVerifier);
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                GetCodeVerifierKey(n.ProtocolMessage.State),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }

        private string RetrieveCodeVerifier(AuthorizationCodeReceivedNotification n)
        {
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);

            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);
            if (codeVerifierCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };

                n.Options.CookieManager.DeleteCookie(n.OwinContext, key, cookieOptions);
            }

            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));
            cookieProperties.Dictionary.TryGetValue("cv", out var codeVerifier);

            return codeVerifier;
        }

        private string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}

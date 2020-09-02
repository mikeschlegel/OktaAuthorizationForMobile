using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OktaAuthorizationForMobile.Models;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace OktaAuthorizationForMobile.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<HomeController> _logger;

        public HomeController(IConfiguration configuration, ILogger<HomeController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secure()
        {
            var idTokenClaim = User.Claims.FirstOrDefault(c => c.Type == "id_token");

            if (idTokenClaim == null || string.IsNullOrWhiteSpace(idTokenClaim.Value)) return RedirectToAction("Error");

            var secureViewModel = new SecureViewModel();
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jsonToken = handler.ReadJwtToken(idTokenClaim.Value);
            foreach (var claim in jsonToken.Claims)
            {
                secureViewModel.IdTokenClaims.Add($"{claim.Type} : {claim.Value}");

            }

            return View(secureViewModel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult LoginWithGoogle()
        {
            if (HttpContext.User.Identity.IsAuthenticated) RedirectToAction("Secure");

            var authSection = _configuration.GetSection("Authentication");
            var authSettings = authSection.Get<AuthSettings>();

            var authUri = authSettings.AuthorizationUrl;
            var idp = authSettings.Idp;
            var clientId = authSettings.ClientId;
            var responseType = "code";
            var scope = HttpUtility.UrlEncode("openid email profile offline_access");
            var redirectUri = HttpUtility.UrlEncode(authSettings.RedirectUrl);
            var state = $"state-{Guid.NewGuid()}";

            var codes = new AuthenticationCodes();

            HttpContext.Session.SetString("codes", JsonSerializer.Serialize(codes));

            return Redirect($"{authUri}?idp={idp}&client_id={clientId}&response_type={responseType}&scope={scope}&redirect_uri={redirectUri}&state={state}&code_challenge_method=S256&code_challenge={codes.CodeChallenge}");
        }

        public async Task<IActionResult> CallbackGoogle(string code)
        {
            if (string.IsNullOrWhiteSpace(code)) return RedirectToAction("Error");

            var authSection = _configuration.GetSection("Authentication");
            var authSettings = authSection.Get<AuthSettings>();

            var codesString = HttpContext.Session.GetString("codes");

            var codes = JsonSerializer.Deserialize<AuthenticationCodes>(codesString);

            var client = new HttpClient();

            var tokenUri = authSettings.TokenUrl;
            var grantType = "authorization_code";
            var redirectUri = authSettings.RedirectUrl;

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", grantType),
                new KeyValuePair<string, string>("client_id", authSettings.ClientId),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("code_verifier", codes.CodeVerifier)
            });

            client.DefaultRequestHeaders.Add("accept", "application/json");
            client.DefaultRequestHeaders.Add("cache-control", "no-cache");

            try
            {
                var response = await client.PostAsync(tokenUri, content);


                if (response.IsSuccessStatusCode)
                {
                    var reponseContent = await response.Content.ReadAsStringAsync();
                    var responseContentObject = JsonSerializer.Deserialize<OktaResponse>(reponseContent);
                    var idToken = responseContentObject.id_token;
                    var accessToken = responseContentObject.access_token;
                    var refreshToken = responseContentObject.refresh_token;

                    //Create a cookie for this user
                    var claims = new List<Claim>
                        {
                            new Claim("id_token", idToken),
                            new Claim("access_token", accessToken),
                            new Claim("refresh_token", refreshToken)
                        };

                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    var authProperties = new AuthenticationProperties
                    {
                        AllowRefresh = true,
                        IsPersistent = true
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    return RedirectToAction("Secure");
                }
            }
            catch (Exception ex)
            {
                var test = ex.Message;
                return RedirectToAction("Error");
            }

            return RedirectToAction("Error");
        }

        [HttpGet]
        public async Task<string> CallApi()
        {
            var claim = User.Claims.FirstOrDefault(c => c.Type == "access_token");

            if (claim == null || string.IsNullOrWhiteSpace(claim.Value)) return "error";

            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("accept", "application/json");
            client.DefaultRequestHeaders.Add("authorization", $"Bearer {claim.Value}");

            var response = await client.GetAsync("https://localhost:6001/secure");
            var content = await response.Content.ReadAsStringAsync();

            return content;
        }
    }

    public class AuthenticationCodes
    {
        public AuthenticationCodes()
        {
            CodeVerifier = CryptoRandom.CreateUniqueId(32);

            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(CodeVerifier));
            CodeChallenge = Base64Url.Encode(challengeBytes);
        }

        public string CodeChallenge { get; set; }
        public string CodeVerifier { get; set; }
    }

    public class OktaResponse
    {
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string scope { get; set; }
        public string access_token { get; set; }
        public string id_token { get; set; }
        public string refresh_token { get; set; }
    }

    public class AuthSettings
    {
        public string AuthorizationUrl { get; set; }
        public string TokenUrl { get; set; }
        public string Idp { get; set; }
        public string ClientId { get; set; }
        public string RedirectUrl { get; set; }
    }
}

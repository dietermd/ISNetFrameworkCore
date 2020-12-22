using IdentityModel.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AspNetWebApplication.Controllers
{
    public class HomeController : Controller
    {
        private readonly HttpClient _httpClient;

        public HomeController()
        {
            _httpClient = new HttpClient { BaseAddress = new Uri("https://localhost:44331/") };
        }

        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult Protected()
        {
            ViewBag.Message = "This is a protected page.";

            var idToken = HttpContext.GetOwinContext().Authentication.User.FindFirst("id_token");
            var accessToken = HttpContext.GetOwinContext().Authentication.User.FindFirst("access_token");

            var _idToken = new JwtSecurityTokenHandler().ReadJwtToken(idToken.Value);
            var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken.Value);

            return View();
        }

        [Authorize]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut("Cookies");
        }

        [Authorize]
        public void LogoutIS()
        {
            HttpContext.GetOwinContext().Authentication.SignOut("oidc");
        }

        [Authorize]
        public async Task<string> CallApi1Async()
        {
            try
            {
                var accessToken = HttpContext.GetOwinContext().Authentication.User.FindFirst("access_token");
                _httpClient.SetBearerToken(accessToken.Value);
                var data = await _httpClient.GetStringAsync("weatherforecast");
                return data;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            
        }
    }
}
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using IdentityServer.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;        
        private readonly IIdentityServerInteractionService _interaction;

        private readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(ILogger<HomeController> logger,
            IIdentityServerInteractionService interaction,
            SignInManager<IdentityUser> signInManager)
        {
            _logger = logger;            
            _interaction = interaction;

            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Protected()
        {
            return View();
        }

        public IActionResult Login(string returnUrl)
        {
            if (User?.Identity.IsAuthenticated == true)
            {
                return RedirectToAction("Index");
            }
            var model = new LoginViewModel { ReturnUrl = returnUrl };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginAsync(LoginViewModel model)
        {            
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);

                if (result.Succeeded)
                {

                    if (context != null || Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        throw new Exception("Invalid return url");
                    }
                }

                ModelState.AddModelError(string.Empty, "Invalid username or password");
            }

            return View(model);
        }

        public async Task<IActionResult> LogoutAsync(string logoutId)
        {
            var logoutContext = await _interaction.GetLogoutContextAsync(logoutId);
            if (User?.Identity.IsAuthenticated == true)
            {
                await _signInManager.SignOutAsync();

                if (logoutContext != null)
                {
                    var vm = new LoggedOutViewModel
                    {
                        AutomaticRedirectAfterSignOut = false,
                        PostLogoutRedirectUri = string.IsNullOrEmpty(logoutContext.PostLogoutRedirectUri) ? Url.Action("Index", "Home") : logoutContext.PostLogoutRedirectUri,
                        ClientName = string.IsNullOrEmpty(logoutContext.ClientName) ? "home page" : logoutContext.ClientName + " application",
                        SignOutIframeUrl = logoutContext.SignOutIFrameUrl,
                        LogoutId = logoutId
                    };

                    return View("LoggedOut", vm);
                }
            }

            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

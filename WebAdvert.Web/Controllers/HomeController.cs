using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using WebAdvert.Web.Models;

namespace WebAdvert.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly SignInManager<CognitoUser> _signInManager;

        public HomeController(ILogger<HomeController> logger, SignInManager<CognitoUser> signInManager)
        {
            _logger = logger;
            _signInManager = signInManager;
        }
        public async Task<IActionResult> Index()
        {
            await _signInManager.SignOutAsync().ConfigureAwait(false);
            return View();
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
    }
}

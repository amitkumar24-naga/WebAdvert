using Amazon.AspNetCore.Identity.Cognito;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;


        public AccountsController(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }
        [HttpGet]
        public async Task<IActionResult> Signup()
        {
            var signupModel = new SignupModel();
            return View(signupModel);
        }

        [HttpGet]
        public async Task<IActionResult> ForgetPassword()
        {
            var forgetPassword = new ForgetPasswordModel();
            return View(forgetPassword);
        }

        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordModel model)
        {

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && user.UserID != null)
            {
                var result = await ((CognitoUserManager<CognitoUser>)_userManager).ResetPasswordAsync(user);
                if (result.Succeeded)
                {
                    TempData["Email"] = model.Email;
                    return RedirectToAction("ResetPassword");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                }
            }
            else
            {
                ModelState.AddModelError("EmailError", "A User with the given email was not found!");
                return View(model);
            }

        }
        [HttpGet]
        public async Task<IActionResult> ResetPassword()
        {
            ViewBag.IsSuccess = false;
            var req = new ResetPasswordModel();
            req.Email =Convert.ToString(TempData["Email"]);
            return View(req);
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            var result = await ((CognitoUserManager<CognitoUser>)_userManager).ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                ViewBag.IsSuccess = true;
                return View();
            }
            else
            {
                ModelState.AddModelError("EmailError", "There is some issue in password reset!");
                return View(model);
            }
        }

        [HttpGet]
        public async Task<IActionResult> Confirm()
        {
            var confirmModel = new ConfirmModel();
            return View(confirmModel);
        }
        [HttpGet]
        public async Task<IActionResult> Login()
        {
            await _signInManager.SignOutAsync().ConfigureAwait(false);
            var loginModel = new LoginModel();
            return View(loginModel);
        }
        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync().ConfigureAwait(false);
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Dashboard()
        {
            var dashBorad = await _userManager.GetUserAsync(new System.Security.Claims.ClaimsPrincipal(Request.HttpContext.User.Identity)).ConfigureAwait(false);
            return View(dashBorad);
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (user.Succeeded)
                {
                    return RedirectToAction("Dashboard");
                }
                else
                {
                    ModelState.AddModelError("Invalid", "Invalid credentials!");
                    return View(model);
                }
            }
            ModelState.AddModelError("Invalid", "Invalid credentials!");
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("Invalid", "Email or code is not valid!");
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("Invalid", "Email or code is not valid!");
                return View(model);
            }
            var result = await ((CognitoUserManager<CognitoUser>)_userManager).ConfirmSignUpAsync(user, model.Code, true);
            if (result.Succeeded)
            {
                return RedirectToAction("Dashboard");
            }
            else
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                }
            }
            return View(model);

        }
        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists!");
                    return View(model);
                }
                //user.Attributes.Add("FirstName", model.FirstName);
                //user.Attributes.Add("LastName", model.LastName);
                //user.Attributes.Add("email", model.Email);
                user.Attributes.Add("address", model.Address);
                user.Attributes.Add("birthdate", model.DateOfirth);

                var createdUser = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);
                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm", "Accounts");
                }
                else
                {
                    foreach (var item in createdUser.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                }
            }
            return View(model);
        }
    }
}
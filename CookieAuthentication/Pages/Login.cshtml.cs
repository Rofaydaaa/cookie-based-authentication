using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace CookieAuthentication.Pages
{
    [BindProperties]
    public class LoginModel : PageModel
    {
        public LoginInput LoginInput { get; set; }
        private readonly ILogger<IndexModel> _logger;

        public LoginModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
        }
        public async Task<IActionResult> OnPostLogin()
        {
            if (ModelState.IsValid)
            {
                if(LoginInput.Username == "intern" && LoginInput.Password == "summer 2023 july")
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, LoginInput.Username),
                        new Claim(ClaimTypes.Role, "Intern"),
                    };
                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    var authProperties = new AuthenticationProperties
                    {
                        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    _logger.LogInformation("User {Email} logged in at {Time}.",
                        LoginInput.Username, DateTime.UtcNow);
                    return RedirectToPage();
                }
                else
                {
                    ModelState.AddModelError("", "Invalid Username or Password");
                }
            }

            return Page();
        }

        public async Task<IActionResult> OnPostLogout()
        {
            // Clear the existing external cookie
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage();
        }
    }

    public class LoginInput
    {
        [Required(ErrorMessage = "Username is required.")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; }
    }
}

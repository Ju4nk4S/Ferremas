#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using BlogCore.Models;
using BlogCore.Utilidades;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

namespace BlogCore.Areas.Identity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _roleManager = roleManager;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            [Display(Name = "Correo electrónico")]
            public string Email { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "La {0} debe tener al menos {2} y un máximo de {1} caracteres.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Contraseña")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirmar contraseña")]
            [Compare("Password", ErrorMessage = "La contraseña y la confirmación de la contraseña no coinciden.")]
            public string ConfirmPassword { get; set; }

            [Required(ErrorMessage = "El nombre es obligatorio")]
            public string Nombre { get; set; }

            [Required(ErrorMessage = "La dirección es obligatoria")]
            public string Direccion { get; set; }

            [Required(ErrorMessage = "La ciudad es obligatoria")]
            public string Ciudad { get; set; }

            [Required(ErrorMessage = "El país es obligatorio")]
            public string Pais { get; set; }

            [Required(ErrorMessage = "El teléfono es obligatorio")]
            [Display(Name = "Teléfono")]
            public string PhoneNumber { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            if (ModelState.IsValid)
            {
                var user = CreateUser();

                user.Nombre = Input.Nombre;
                user.Direccion = Input.Direccion;
                user.Ciudad = Input.Ciudad;
                user.Pais = Input.Pais;
                user.PhoneNumber = Input.PhoneNumber;

                await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);
                var result = await _userManager.CreateAsync(user, Input.Password);

                if (result.Succeeded)
                {
                    if (!await _roleManager.RoleExistsAsync(CNT.Administrador))
                    {
                        await _roleManager.CreateAsync(new IdentityRole(CNT.Administrador));
                        await _roleManager.CreateAsync(new IdentityRole(CNT.Registrado));
                        await _roleManager.CreateAsync(new IdentityRole(CNT.Cliente));
                    }

                    string rol = Request.Form["radUsuarioRole"].ToString();

                    if (rol == CNT.Administrador)
                    {
                        await _userManager.AddToRoleAsync(user, CNT.Administrador);
                    }
                    else
                    {
                        if (rol == CNT.Registrado)
                        {
                            await _userManager.AddToRoleAsync(user, CNT.Registrado);
                        }
                        else
                        {
                            await _userManager.AddToRoleAsync(user, CNT.Cliente);
                        }
                    }

                    _logger.LogInformation("El usuario creó una nueva cuenta con contraseña.");

                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"No se puede crear una instancia de '{nameof(ApplicationUser)}'. " +
                    $"Asegúrate de que '{nameof(ApplicationUser)}' no sea una clase abstracta y tenga un constructor sin parámetros, o alternativamente " +
                    $"sobrescribe la página de registro en /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("La UI predeterminada requiere una tienda de usuarios con soporte de correo electrónico.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}

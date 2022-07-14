using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.Net.Http.Headers;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;

namespace AzureTest.Controllers
{
	[Route("B2CAccount")]
	public class B2CAccountController : Controller
	{
		[HttpGet("{scheme?}")]
		[Route("SignIn")]
		public IActionResult SignIn([FromRoute] string scheme)
		{

			scheme ??= OpenIdConnectDefaults.AuthenticationScheme;

			if (!User.Identity.IsAuthenticated)
			{
				string redirectUrl = Request.Headers["Referer"].ToString().Replace($"{Request.Scheme}://{Request.Host.ToUriComponent()}", string.Empty);

				return Challenge(new AuthenticationProperties() { RedirectUri = $"/B2CAccount/Callback?redirectUrl={redirectUrl}" }, scheme);
			}

			return Forbid();
		}

		[Route("EditProfile")]
		public async Task<IActionResult> EditProfileAsync([FromRoute] string scheme)
		{
			scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
			var authenticated = await HttpContext.AuthenticateAsync(scheme).ConfigureAwait(false);

			if (!authenticated.Succeeded)
				return Challenge(scheme);

			string redirectUrl = Request.Headers["Referer"].ToString().Replace($"{Request.Scheme}://{Request.Host.ToUriComponent()}", string.Empty);

			var properties = new AuthenticationProperties { RedirectUri = redirectUrl, };
			properties.Items[Constants.Policy] = "B2C_1_EditProfile";
			return Challenge(properties, scheme);
		}

		[Route("SignOut")]
		public IActionResult SignOut([FromRoute] string scheme)
		{
			if (AppServicesAuthenticationInformation.IsAppServicesAadAuthenticationEnabled)
				return LocalRedirect(AppServicesAuthenticationInformation.LogoutUrl);

			scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
			string redirectUrl = Request.Headers["Referer"].ToString().Replace($"{Request.Scheme}://{Request.Host.ToUriComponent()}", string.Empty);
			//var callbackUrl = Url.Page("/", pageHandler: null, values: null, protocol: Request.Scheme);

			return SignOut(
				 new AuthenticationProperties
				 {
					 RedirectUri = redirectUrl,
				 },
				 CookieAuthenticationDefaults.AuthenticationScheme,
				 scheme);
		}

	}
}

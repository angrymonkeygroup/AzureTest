using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;

namespace AzureTest.Controllers
{

	[Route("B2CAccount")]
	public class B2CAccountController : Controller
	{
		//private IConfidentialClientApplication _clientApplication { get; set; }
		//private GraphServiceClient _microsoftGraph;
		//private GraphServiceClient MicrosoftGraph => _microsoftGraph ??= new(new ClientCredentialProvider(_clientApplication));


		[HttpGet("{scheme?}")]
		[Route("SignIn")]
		public IActionResult SignIn([FromRoute] string scheme)
		{
			scheme ??= OpenIdConnectDefaults.AuthenticationScheme;

			if (!User.Identity.IsAuthenticated)
			{
				string redirectUrl = Request.Headers["Referer"].ToString().Replace($"{Request.Scheme}://{Request.Host.ToUriComponent()}", string.Empty);
				return Challenge(new AuthenticationProperties() { RedirectUri = "https://localhost:7176/" }, scheme);
			}

			return Forbid();
		}

        public async Task<IActionResult> CallbackAsync(string redirectUrl)
        {
            //Guid userId = new(User.Claims.SingleOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value);

            //UserModel user = await GetUserAsync(userId);

            //if (string.IsNullOrEmpty(user.EmailAddress))
            //{
            //    string email = User.Claims.SingleOrDefault(key => key.Type == "emails")?.Value;

            //    try
            //    {
            //        await UpdateUserEmail(userId, email);
            //    }
            //    catch { }

            //    return Redirect("~/MicrosoftIdentity/Account/SignOut");
            //}

            return Redirect(redirectUrl);
        }




  //      [Route("EditProfile")]
		//public async Task<IActionResult> EditProfileAsync([FromRoute] string scheme)
		//{
		//	scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
		//	var authenticated = await HttpContext.AuthenticateAsync(scheme).ConfigureAwait(false);

		//	if (!authenticated.Succeeded)
		//		return Challenge(scheme);

		//	string redirectUrl = Request.Headers["Referer"].ToString().Replace($"{Request.Scheme}://{Request.Host.ToUriComponent()}", string.Empty);

		//	var properties = new AuthenticationProperties { RedirectUri = redirectUrl, };
		//	properties.Items[Microsoft.Identity.Web.Constants.Policy] = "B2C_1_EditProfile";
		//	return Challenge(properties, scheme);
		//}

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

		//public async Task<UserModel> GetUserAsync(Guid userId)
		//{

		//	User graphUser = await MicrosoftGraph.Users[userId.ToString()].Request().GetAsync();

		//	return Parse(graphUser);

		//}

		//public async Task UpdateUserEmail(Guid userId, string email)
		//{
		//	await MicrosoftGraph.Users[userId.ToString()].Request()
		//		.UpdateAsync(new Microsoft.Graph.User
		//		{
		//			Mail = email,
		//		});
		//}

		//private UserModel Parse(Microsoft.Graph.User graphUser)
		//{
		//	UserModel user = new()
		//	{
		//		FirstName = graphUser.GivenName,
		//		LastName = graphUser.Surname,
		//		EmailAddress = graphUser.Mail,
		//		City = graphUser.City,
		//		StreetAddress = graphUser.StreetAddress,
		//		ID = new Guid(graphUser.Id),
		//	};

		//	if (graphUser.AdditionalData == null)
		//		return user;


		//	return user;
		//}

	}
}

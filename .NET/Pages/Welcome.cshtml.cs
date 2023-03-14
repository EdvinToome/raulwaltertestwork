namespace WebEid.AspNetCore.Example.Pages
{
    using System.Linq;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public class WelcomeModel : PageModel
    {
        public string PrincipalName => GetPrincipalName((ClaimsIdentity)this.User.Identity);

        private static string GetPrincipalName(ClaimsIdentity identity)
        {
            var givenName = identity.Claims.Where(claim => claim.Type == ClaimTypes.GivenName)
                .Select(claim => claim.Value)
                .SingleOrDefault();
            var surname = identity.Claims.Where(claim => claim.Type == ClaimTypes.Surname)
                .Select(claim => claim.Value)
                .SingleOrDefault();
            var commonName = identity.Claims.Where(claim => claim.Type == ClaimTypes.Name) // Task 3: Add organization common name support
                .Select(claim => claim.Value)
                .SingleOrDefault();
            if (string.IsNullOrWhiteSpace(givenName) || string.IsNullOrWhiteSpace(surname)) {
                return commonName;
            }
            else {
                return $"{givenName} {surname}";
            }
        }
    }
}

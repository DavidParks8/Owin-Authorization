using System.Security.Claims;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using Microsoft.Owin.Security.Authorization;
using Microsoft.Owin.Security.Authorization.WebApi;

namespace WebApi_Classic.Controllers
{
    public class ExampleController : ApiController, IAuthorizationController
    {
        private void SetupDemo()
        {
            var currentIdentity = (ClaimsIdentity)HttpContext.Current.User.Identity;
            if (!currentIdentity.HasClaim(x => x.Type == "EmployeeNumber"))
            {
                const string currentEmployeeNumber = "2";
                currentIdentity.AddClaim(new Claim("EmployeeNumber", currentEmployeeNumber));
            }
        }
        public AuthorizationOptions AuthorizationOptions { get; }

        public ExampleController()
        {
            var options = new AuthorizationOptions();
            options.AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"));
            options.AddPolicy("EmployeeNumber6", policy => policy.RequireClaim("EmployeeNumber", "6"));

            AuthorizationOptions = options;

            SetupDemo();
        }

        [HttpGet]
        [ResourceAuthorize(Policy = "EmployeeOnly")]
        public IHttpActionResult Authorized()
        {
            return Json("You are authorized!");
        }

        [HttpGet]
        [ResourceAuthorize(Policy = "EmployeeNumber6")]
        public IHttpActionResult Denied()
        {
            return Json("You should never be presented this text because you will never be authorized to see it");
        }
    }
}

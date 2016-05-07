using System.Security.Claims;
using System.Web.Mvc;
using Microsoft.Owin.Security.Authorization;
using Microsoft.Owin.Security.Authorization.Mvc;
using AuthorizationContext = System.Web.Mvc.AuthorizationContext;

namespace MVC_Classic.Controllers
{
    public class HomeController : Controller, IAuthorizationController
    {
        // this function will execute before evaluating resource authorization
        protected override void OnAuthorization(AuthorizationContext filterContext)
        {
            var principal = (ClaimsPrincipal)User;
            var identity = (ClaimsIdentity)principal.Identity;
            if (!identity.HasClaim(x => x.Type == "EmployeeNumber"))
            {
                identity.AddClaim(new Claim("EmployeeNumber", "5"));
            }

            base.OnAuthorization(filterContext);
        }

        public AuthorizationOptions AuthorizationOptions { get; }

        public HomeController()
        {
            var options = new AuthorizationOptions();
            options.AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"));
            options.AddPolicy("EmployeeNumber6", policy => policy.RequireClaim("EmployeeNumber", "6"));

            AuthorizationOptions = options;
        }

        public ActionResult Index()
        {
            return View();
        }

        [ResourceAuthorize(Policy = "EmployeeOnly")]
        public ActionResult Authorized()
        {
            return View();
        }

        [ResourceAuthorize(Policy = "EmployeeNumber6")]
        public ActionResult Denied()
        {
            return new EmptyResult();
        }
    }
}
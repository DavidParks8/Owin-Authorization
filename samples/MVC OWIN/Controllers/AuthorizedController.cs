using System.Security.Claims;
using System.Web.Mvc;
using Microsoft.Owin.Security.Authorization.Mvc;
using AuthorizationContext = System.Web.Mvc.AuthorizationContext;

namespace MVC_OWIN.Controllers
{
    [ResourceAuthorize(Policy = "EmployeeOnly")]
    public class AuthorizedController : Controller
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

        public ActionResult Index()
        {
            return View();
        }
    }
}
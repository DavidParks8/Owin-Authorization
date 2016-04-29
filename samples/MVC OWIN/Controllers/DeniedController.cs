using System.Web.Mvc;
using Microsoft.Owin.Security.Authorization;

namespace MVC_OWIN.Controllers
{
    [ResourceAuthorize(Policy = "EmployeeNumber6")]
    public class DeniedController : Controller
    {
        public ActionResult Index()
        {
            return new EmptyResult();
        }
    }
}
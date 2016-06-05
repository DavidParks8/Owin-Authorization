using System.Web.Http;
using Microsoft.Owin.Security.Authorization.WebApi;

namespace WebApi_Custom_Handler.Controllers
{
    public class ExampleController : ApiController
    {
        [HttpGet]
        [ResourceAuthorize(Policy = ExampleConstants.EmployeeNumber2Policy)]
        public IHttpActionResult Authorized()
        {
            return Json("You are authorized!");
        }

        [HttpGet]
        [ResourceAuthorize(Roles = "admin")]
        public IHttpActionResult Denied()
        {
            return Json("You should never be presented this text because you will never be authorized to see it");
        }
    }
}

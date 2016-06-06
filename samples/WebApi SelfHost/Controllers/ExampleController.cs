using System.Web.Http;
using Microsoft.Owin.Security.Authorization.WebApi;

namespace WebApi_SelfHost.Controllers
{
    public class ExampleController : ApiController
    {
        [HttpGet]
        [ResourceAuthorize(Policy = ExampleConstants.EmployeeOnlyPolicy)]
        public IHttpActionResult Authorized()
        {
            return Json("You are authorized!");
        }

        [HttpGet]
        [ResourceAuthorize(Policy = ExampleConstants.EmployeeNumber6Policy)]
        public IHttpActionResult Denied()
        {
            return Json("You should never be presented this text because you will never be authorized to see it");
        }

        public IHttpActionResult Test()
        {
            return Json("You are authorized!");
        }
    }
}

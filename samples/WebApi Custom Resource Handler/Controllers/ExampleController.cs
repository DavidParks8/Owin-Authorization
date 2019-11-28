using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Results;
using Microsoft.Owin.Security.Authorization;
using Microsoft.Owin.Security.Authorization.WebApi;
using WebApi_Custom_Resource_Handler.Models;

namespace WebApi_Custom_Resource_Handler.Controllers
{
    public class ExampleController : ApiController
    {
        private IAuthorizationService authorizatonService;


        [HttpGet]
        [ResourceAuthorize(Policy = ExampleConstants.EmployeeOnlyPolicy)]
        public async Task<JsonResult<string>> Authorized()
        {
            //Retrieve AuthorizeService
            authorizatonService =   OwinContextExtensions.GetAuthorizationService(HttpContext.Current.GetOwinContext());

            //Replace this code with actual code to retreive employee from datastore
            var employee = new Employee { Id = 5, Name = "Willy Waldo" };
        
            //This will fail when you don't have the employee claim with the corresponding Id...
            if (!(await authorizatonService.AuthorizeAsync((ClaimsPrincipal)User, employee, ExampleConstants.EmployeeDataAccessPolicy)))
            {
                return Json("You are not authorized to access the requested employee!");
            }
            return Json("You are authorized!");
        }

        [HttpGet]
        [ResourceAuthorize(Policy = ExampleConstants.EmployeeNumber6Policy)]
        public IHttpActionResult Denied()
        {
            return Json("You should never be presented this text because you will never be authorized to see it");
        }
    }
}

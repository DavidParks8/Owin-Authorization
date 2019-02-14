using Microsoft.Owin.Security.Authorization;
using System.Linq;
using System.Threading.Tasks;
using WebApi_Custom_Resource_Handler.Models;

namespace WebApi_Custom_Resource_Handler
{
    public class HasEmployeeNumberHandler : AuthorizationHandler<HasEmployeeNumberRequirement>
    {
        public HasEmployeeNumberHandler()
        {
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HasEmployeeNumberRequirement requirement)
        {
            var employee = context.Resource as Employee;
            if (context.User.Claims.Any(c => c.Type == ExampleConstants.EmployeeClaimType && c.Value == employee.Id.ToString()))
                context.Succeed(requirement);
            return Task.FromResult(0);
        }
    }
}
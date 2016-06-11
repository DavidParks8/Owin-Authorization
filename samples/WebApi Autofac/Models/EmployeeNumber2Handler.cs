using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization;

namespace WebApi_Autofac.Models
{
    public class EmployeeNumber2Handler : AuthorizationHandler<EmployeeNumber2Requirement>
    {
        private static int _counter = 0;

        public EmployeeNumber2Handler(ILogger logger)
        {
            _counter++;
            if (_counter >= 3)
                _counter = 0;

            logger.WriteInformation("current: " + _counter);
        }

        protected override void Handle(AuthorizationContext context, EmployeeNumber2Requirement requirement)
        {
            foreach (var claim in context.User.Claims)
            {
                if (string.Equals(claim.Type, ExampleConstants.EmployeeClaimType))
                {
                    if (claim.Value == _counter.ToString())
                    {
                        context.Succeed(requirement);
                        return;
                    }
                }
            }
        }
    }
}
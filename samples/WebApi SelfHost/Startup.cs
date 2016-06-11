using System;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Owin;

namespace WebApi_SelfHost
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseErrorPage();
            app.Use(AddEmployeeClaimBeforeAuthorizationCheck);
            var config = new HttpConfiguration();
            WebApiConfig.Register(config);
            
            app.UseAuthorization(options =>
            {
                options.AddPolicy(ExampleConstants.EmployeeOnlyPolicy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType));
                options.AddPolicy(ExampleConstants.EmployeeNumber6Policy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType, "6"));
            });
            app.UseWebApi(config);
        }

        private static async Task AddEmployeeClaimBeforeAuthorizationCheck(IOwinContext owinContext, Func<Task> next)
        {
            if (owinContext.Authentication.User == null)
            {
                owinContext.Authentication.User = new ClaimsPrincipal(new ClaimsIdentity());
            }
            var currentIdentity = (ClaimsIdentity) owinContext.Authentication.User.Identity;
            if (!currentIdentity.HasClaim(x => x.Type == ExampleConstants.EmployeeClaimType))
            {
                const string currentEmployeeNumber = "2";
                currentIdentity.AddClaim(new Claim(ExampleConstants.EmployeeClaimType, currentEmployeeNumber));
            }

            await next();
        }
    }
}
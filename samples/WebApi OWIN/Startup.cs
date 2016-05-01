using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using System.Web.Http;

[assembly: OwinStartup(typeof(WebApi_OWIN.Startup))]

namespace WebApi_OWIN
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Use(AddEmployeeClaimBeforeAuthorizationCheck);

            app.UseAuthorization(options =>
            {
                options.AddPolicy(ExampleConstants.EmployeeOnlyPolicy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType));
                options.AddPolicy(ExampleConstants.EmployeeNumber6Policy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType, "6"));
            });

            var config = new HttpConfiguration();
            WebApiConfig.Register(config);
            app.UseWebApi(config);
        }

        private async Task AddEmployeeClaimBeforeAuthorizationCheck(IOwinContext owinContext, Func<Task> next)
        {
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
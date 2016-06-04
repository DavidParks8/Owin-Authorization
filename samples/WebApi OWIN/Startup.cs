using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using System.Web.Http;
using Microsoft.Owin.Cors;

[assembly: OwinStartup(typeof(WebApi_OWIN.Startup))]

namespace WebApi_OWIN
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseErrorPage();
            app.Use(AddEmployeeClaimBeforeAuthorizationCheck);

            var config = new HttpConfiguration();
            WebApiConfig.Register(config);
            config.EnableCors();

            app.UseCors(CorsOptions.AllowAll);

            app.UseAuthorization(options =>
            {
                options.AddPolicy(ExampleConstants.EmployeeOnlyPolicy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType));
                options.AddPolicy(ExampleConstants.EmployeeNumber6Policy, policyBuilder => policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType, "6"));
                options.AddPolicy(ExampleConstants.EmployeeNumber2Policy, policyBuilder => policyBuilder.AddRequirements(new EmployeeNumber2Requirement()));
                options.Dependencies.AdditionalHandlers.Add(new EmployeeNumber2Handler());
            });

            app.UseWebApi(config);
        }

        private static async Task AddEmployeeClaimBeforeAuthorizationCheck(IOwinContext owinContext, Func<Task> next)
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
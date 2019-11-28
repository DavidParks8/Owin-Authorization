using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using System.Web.Http;
using System.Web.Http.Filters;
using Microsoft.Owin.Security.Authorization;

[assembly: OwinStartup(typeof(WebApi_Custom_Resource_Handler.Startup))]

namespace WebApi_Custom_Resource_Handler
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
                options.AddPolicy(ExampleConstants.EmployeeDataAccessPolicy, policyBuilder => policyBuilder.AddRequirements(new HasEmployeeNumberRequirement()));


                var policyProvider = new DefaultAuthorizationPolicyProvider(options);
                options.Dependencies.PolicyProvider = policyProvider;
                options.Dependencies.Service = new DefaultAuthorizationService(policyProvider, new[] { new HasEmployeeNumberHandler() });

            });

            //config.Filters.Add(new ResourceAccessControl());
            app.UseWebApi(config);

            SwaggerConfig.Register(config);

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
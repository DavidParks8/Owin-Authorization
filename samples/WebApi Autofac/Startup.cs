using System;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Autofac;
using Autofac.Integration.WebApi;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Owin;
using WebApi_Autofac;

[assembly: OwinStartup(typeof(Startup))]

namespace WebApi_Autofac
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseErrorPage();
            app.Use(AddEmployeeClaimBeforeAuthorizationCheck);
            
            var config = new HttpConfiguration();
            WebApiConfig.Register(config);

            var options = new AuthorizationOptions();
            options.AddPolicy(ExampleConstants.EmployeeNumber2Policy, policyBuilder =>
            {
                policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType, "2");
            });

            var builder = new ContainerBuilder();
            builder.RegisterApiControllers(Assembly.GetExecutingAssembly());
            builder.Register(resolver => options)
                .As<AuthorizationOptions>().ExternallyOwned();
            builder.Register(resolver => app.GetLoggerFactory())
                .As<ILoggerFactory>();
            builder.Register(resolver => resolver.Resolve<ILoggerFactory>().Create("default"))
                .As<ILogger>();
            builder.RegisterType<DefaultAuthorizationPolicyProvider>()
                .As<IAuthorizationPolicyProvider>();
            builder.Register(resolver => new DefaultAuthorizationService(
                resolver.Resolve<IAuthorizationPolicyProvider>(),
                new[] {new PassThroughAuthorizationHandler()}))
                .As<IAuthorizationService>();
            
            var container = builder.Build();

            options.Dependencies = new AutofacAuthorizationDependencies(container);
            config.DependencyResolver = new AutofacWebApiDependencyResolver(container);
            
            app.UseAutofacMiddleware(container);
            app.UseAutofacWebApi(config);

            app.UseAuthorization(options);

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
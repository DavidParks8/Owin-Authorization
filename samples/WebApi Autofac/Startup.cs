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
using WebApi_Autofac.Models;

[assembly: OwinStartup(typeof(Startup))]

namespace WebApi_Autofac
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseErrorPage();
            app.Use(AddEmployeeClaimBeforeAuthorizationCheck);
            
            var builder = new ContainerBuilder();

            var config = new HttpConfiguration();
            WebApiConfig.Register(config);

            builder.RegisterApiControllers(Assembly.GetExecutingAssembly());

            builder.RegisterType<DefaultAuthorizationPolicyProvider>().As<IAuthorizationPolicyProvider>().InstancePerRequest();
            builder.RegisterAssemblyTypes(Assembly.GetExecutingAssembly()).Where(t => typeof(IAuthorizationHandler).IsAssignableFrom(t)).InstancePerRequest().AsImplementedInterfaces();
            builder.RegisterType<PassThroughAuthorizationHandler>().As<IAuthorizationHandler>().InstancePerRequest();
            builder.RegisterType<DefaultAuthorizationService>().As<IAuthorizationService>().InstancePerRequest();
            builder.RegisterType<AuthorizationDependencies>().InstancePerRequest().PropertiesAutowired();
            builder.RegisterInstance(new DiagnosticsLoggerFactory().Create("WebApi_Autofac_Logger"))
                .As<ILogger>()
                .SingleInstance();

            var container = builder.Build();
            config.DependencyResolver = new AutofacWebApiDependencyResolver(container);

            app.UseAutofacMiddleware(container);
            app.UseAutofacWebApi(config);

            app.UseAuthorization(options =>
            {
                options.AddPolicy(ExampleConstants.EmployeeNumber2Policy, policyBuilder =>
                {
                    policyBuilder.RequireClaim(ExampleConstants.EmployeeClaimType, "2");
                });

                options.DependenciesFactory = new AutofacAuthorizationDependenciesFactory();
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
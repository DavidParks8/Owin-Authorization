using System;
using Autofac;
using Autofac.Core;
using Autofac.Integration.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Authorization;

namespace WebApi_Autofac
{
    public class AutofacAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        public AuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            var optionsParameter = new ResolvedParameter(
                        (pi, ctx) => pi.ParameterType == typeof(AuthorizationOptions),
                        (pi, ctx) => options);

            owinContext.GetAutofacLifetimeScope().Resolve<IAuthorizationPolicyProvider>(optionsParameter);
            var dependenciesFactory = owinContext.GetAutofacLifetimeScope().Resolve<Func<AuthorizationOptions, AuthorizationDependencies>>();
            var dependencies = dependenciesFactory?.Invoke(options);
            return dependencies;
        }
    }
}
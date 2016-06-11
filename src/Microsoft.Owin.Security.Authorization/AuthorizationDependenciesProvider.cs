using System;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationDependenciesProvider : IAuthorizationDependenciesProvider
    {
        public AuthorizationDependenciesProvider(
            Func<AuthorizationOptions, IOwinContext, AuthorizationDependencies> onCreate = null,
            Action<AuthorizationOptions, IOwinContext, AuthorizationDependencies> onDispose = null)
        {
            OnCreate = onCreate;
            OnDispose = onDispose;
        }

        public Func<AuthorizationOptions, IOwinContext, AuthorizationDependencies> OnCreate { get; }

        public Action<AuthorizationOptions, IOwinContext, AuthorizationDependencies> OnDispose { get; }

        public static AuthorizationDependenciesProvider CreateDefault(IAuthorizationHandler[] handlers = null, ILoggerFactory loggerFactory = null)
        {
            return new AuthorizationDependenciesProvider((options, context) =>
            {
                var policyProvider = new DefaultAuthorizationPolicyProvider(options);
                return new AuthorizationDependencies
                {
                    PolicyProvider = policyProvider,
                    Service = new DefaultAuthorizationService(
                        policyProvider,
                        handlers ?? new IAuthorizationHandler[] {new PassThroughAuthorizationHandler()},
                        loggerFactory?.Create("ResourceAuthorization"))
                };
            });
        }
    }
}
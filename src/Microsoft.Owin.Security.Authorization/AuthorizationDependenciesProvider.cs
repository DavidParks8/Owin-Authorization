using System;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationDependenciesProvider
    {
        public AuthorizationDependenciesProvider(IAuthorizationPolicyProvider policyProvider = null,
            IAuthorizationHandler[] handlers = null, ILoggerFactory loggerFactory = null)
        {
            OnCreate = options =>
            {
                policyProvider = policyProvider ?? new DefaultAuthorizationPolicyProvider(options);
                handlers = handlers ?? new IAuthorizationHandler[] {new PassThroughAuthorizationHandler()};
                loggerFactory = loggerFactory ?? new DiagnosticsLoggerFactory();
                return new AuthorizationDependencies
                {
                    PolicyProvider = policyProvider,
                    Service = new DefaultAuthorizationService(
                        policyProvider,
                        handlers,
                        loggerFactory.Create("ResourceAuthorization"))
                };
            };
            OnDispose = (options, context) => { };
        }

        public Func<AuthorizationOptions, AuthorizationDependencies> OnCreate { get; set; }

        public Action<AuthorizationOptions, AuthorizationDependencies> OnDispose { get; set; }

        public virtual AuthorizationDependencies Create(AuthorizationOptions options)
        {
            return OnCreate(options);
        }

        public virtual void Dispose(AuthorizationOptions options, AuthorizationDependencies dependencies)
        {
            OnDispose(options, dependencies);
        }
    }
}
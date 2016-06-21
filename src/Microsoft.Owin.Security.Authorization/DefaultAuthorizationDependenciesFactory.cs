using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class DefaultAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        private readonly IAuthorizationHandler[] _handlers;

        public DefaultAuthorizationDependenciesFactory(params IAuthorizationHandler[] handlers)
        {
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = handlers;
        }

        public IAuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var handlerProvider = new DefaultAuthorizationHandlerProvider(_handlers);
            return new AuthorizationDependencies
            {
                LoggerFactory = new DiagnosticsLoggerFactory(),
                PolicyProvider = policyProvider,
                HandlerProvider = handlerProvider
            };
        }
    }
}
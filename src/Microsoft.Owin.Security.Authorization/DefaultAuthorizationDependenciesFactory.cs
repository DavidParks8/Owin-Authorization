using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace Microsoft.Owin.Security.Authorization
{
    public class DefaultAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        private readonly ILoggerFactory _loggerFactory;

        private readonly IAuthorizationHandler[] _handlers;

        public DefaultAuthorizationDependenciesFactory(ILoggerFactory loggerFactory, params IAuthorizationHandler[] handlers)
        {
            _loggerFactory = loggerFactory;
            _handlers = handlers;
        }

        public AuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var handlers = new List<IAuthorizationHandler>();
            if (_handlers != null)
            {
                handlers.AddRange(_handlers);
            }
            handlers.Add(new PassThroughAuthorizationHandler());
            return new AuthorizationDependencies
            {
                PolicyProvider = policyProvider,
                Service = new DefaultAuthorizationService(
                    policyProvider,
                    handlers,
                    _loggerFactory?.Create("ResourceAuthorization"))
            };
        }
    }
}
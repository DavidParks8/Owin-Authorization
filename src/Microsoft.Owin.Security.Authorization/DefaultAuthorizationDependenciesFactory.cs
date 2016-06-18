using Microsoft.Owin.Logging;

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

        public IAuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            return new AuthorizationDependencies
            {
                LoggerFactory = _loggerFactory,
                PolicyProvider = policyProvider,
                Handlers = _handlers
            };
        }
    }
}
using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationDependenciesFactory"/>.
    /// </summary>
    public class DefaultAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        private readonly IAuthorizationHandler[] _handlers;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationDependenciesFactory"/>.
        /// </summary>
        /// <param name="handlers">The <see cref="IAuthorizationHandler"/>s used in creating an <see cref="IAuthorizationDependencies"/> object.</param>
        public DefaultAuthorizationDependenciesFactory(params IAuthorizationHandler[] handlers)
        {
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = handlers;
        }

        /// <summary>
        /// Creates an <see cref="IAuthorizationDependencies"/> from the given <paramref name="options"/> and <paramref name="owinContext"/>.
        /// </summary>
        /// <param name="options">The <see cref="AuthorizationOptions"/> to use during <see cref="IAuthorizationDependencies"/> creation.</param>
        /// <param name="owinContext">The <see cref="IOwinContext"/> to use during <see cref="IAuthorizationDependencies"/> creation.</param>
        /// <returns>The <see cref="IAuthorizationDependencies"/> instance.</returns>
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
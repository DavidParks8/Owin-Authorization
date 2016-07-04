using System;
using System.Collections.Generic;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of <see cref="IAuthorizationServiceFactory"/>.
    /// </summary>
    public class DefaultAuthorizationServiceFactory : IAuthorizationServiceFactory
    {
        /// <summary>
        /// Creates a new <see cref="IAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> for providing policies.</param>
        /// <param name="authorizationHandlers">A set <see cref="IAuthorizationHandler"/>s for evaluating authorization.</param>
        /// <param name="loggerFactory">An <see cref="ILoggerFactory"/> for logging.</param>
        public IAuthorizationService Create(
            IAuthorizationPolicyProvider policyProvider,
            IEnumerable<IAuthorizationHandler> authorizationHandlers,
            ILoggerFactory loggerFactory)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (authorizationHandlers == null)
            {
                throw new ArgumentNullException(nameof(authorizationHandlers));
            }
            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            var logger = loggerFactory.Create("ResourceAuthorization");
            return new DefaultAuthorizationService(policyProvider, authorizationHandlers, logger);
        }
    }
}
using System;
using System.Collections.Generic;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationServiceFactory"/>.
    /// </summary>
    public class DefaultAuthorizationServiceFactory : IAuthorizationServiceFactory
    {
        /// <summary>
        /// Creates a new <see cref="IAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> for providing policies.</param>
        /// <param name="authorizationHandlers">A set <see cref="IAuthorizationHandler"/>s for evaluating authorization.</param>
        /// <param name="loggerFactory">An <see cref="ILoggerFactory"/> for logging.</param>
        /// <param name="evaluator">The <see cref="IAuthorizationEvaluator"/> used to determine if authorzation was successful.</param>
        public IAuthorizationService Create(
            IAuthorizationPolicyProvider policyProvider,
            IEnumerable<IAuthorizationHandler> authorizationHandlers,
            ILoggerFactory loggerFactory,
            IAuthorizationEvaluator evaluator)
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
            if (evaluator == null)
            {
                throw new ArgumentNullException(nameof(evaluator));
            }

            var logger = loggerFactory.Create("ResourceAuthorization");
            return new DefaultAuthorizationService(policyProvider, authorizationHandlers, logger, evaluator);
        }
    }
}
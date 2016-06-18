using System;
using System.Collections.Generic;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class DefaultAuthorizationServiceFactory : IAuthorizationServiceFactory
    {
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
using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationServiceFactory
    {
        IAuthorizationService Create(
            IAuthorizationPolicyProvider policyProvider,
            IAuthorizationHandler[] authorizationHandlers,
            ILoggerFactory loggerFactory);
    }

    public class DefaultAuthorizationServiceFactory : IAuthorizationServiceFactory
    {
        public IAuthorizationService Create(
            IAuthorizationPolicyProvider policyProvider,
            IAuthorizationHandler[] authorizationHandlers,
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

    public interface IAuthorizationDependencies
    {
        IAuthorizationServiceFactory ServiceFactory { get; set; }
        ILoggerFactory LoggerFactory { get; set; }
        IAuthorizationPolicyProvider PolicyProvider { get; set; }
        IAuthorizationHandler[] Handlers { get; set; }
    }
}
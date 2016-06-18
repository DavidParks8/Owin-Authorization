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
}
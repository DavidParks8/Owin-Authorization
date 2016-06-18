using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationDependencies : IAuthorizationDependencies
    {
        public IAuthorizationServiceFactory ServiceFactory { get; set; }
        public IAuthorizationPolicyProvider PolicyProvider { get; set; }
        public IAuthorizationHandlerProvider HandlerProvider { get; set; }
        public ILoggerFactory LoggerFactory { get; set; }
    }
}
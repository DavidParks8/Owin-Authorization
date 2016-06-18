using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationDependencies
    {
        IAuthorizationServiceFactory ServiceFactory { get; set; }
        ILoggerFactory LoggerFactory { get; set; }
        IAuthorizationPolicyProvider PolicyProvider { get; set; }
        IAuthorizationHandler[] Handlers { get; set; }
    }
}
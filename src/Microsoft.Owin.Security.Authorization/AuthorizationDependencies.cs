using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationDependencies
    {
        public IAuthorizationService Service { get; set; }

        public ILoggerFactory LoggerFactory { get; set; }
    }
}
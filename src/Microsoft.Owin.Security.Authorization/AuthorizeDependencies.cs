using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizeDependencies
    {
        public Func<IAuthorizationService> Service { get; set; }
        public Func<IAuthorizationPolicyProvider> PolicyProvider { get; set; }
        public Func<IAuthorizationHandler> Handler { get; set; }

        public ILoggerFactory LoggerFactory { get; set; } = new DiagnosticsLoggerFactory();
    }
}
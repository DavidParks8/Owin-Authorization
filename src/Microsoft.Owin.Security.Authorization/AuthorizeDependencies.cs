using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizeDependencies
    {
        public IAuthorizationService Service { get; set; }

        public ILoggerFactory LoggerFactory { get; set; } = new DiagnosticsLoggerFactory();
    }
}
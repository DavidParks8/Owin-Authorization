using System.Collections.Generic;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationDependencies
    {
        public IList<IAuthorizationHandler> AdditionalHandlers { get; } = new List<IAuthorizationHandler>();

        public IAuthorizationService Service { get; set; }

        public ILoggerFactory LoggerFactory { get; set; }
    }
}
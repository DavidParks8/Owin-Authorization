using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware
    {
        public const string ServiceKey = "idm:resourceAuthorizationService";

        private readonly Func<IDictionary<string, object>, Task> _next;
        private AuthorizationOptions _options;

        public ResourceAuthorizationMiddleware(Func<IDictionary<string, object>, Task> next, AuthorizationOptions options)
        {
            _options = options;
            _next = next;
        }

        public async Task Invoke(IDictionary<string, object> environment)
        {
            environment[ServiceKey] = _options.Dependencies.Service();
            await _next(environment);
        }
    }
}

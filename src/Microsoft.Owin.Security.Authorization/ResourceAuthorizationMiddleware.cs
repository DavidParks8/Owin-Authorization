using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware
    {
        public const string ServiceKey = "idm:resourceAuthorizationService";
        public const string PolicyKey = "idm:resourceAuthorizationPolicy";

        private readonly Func<IDictionary<string, object>, Task> _next;
        private AuthorizationOptions _options;

        public ResourceAuthorizationMiddleware(Func<IDictionary<string, object>, Task> next, AuthorizationOptions options)
        {
            _options = options;
            _next = next;
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            env[ServiceKey] = _options.Dependencies.Service();
            env[PolicyKey] = _options.Dependencies.PolicyProvider();
            await _next(env);
        }
    }
}

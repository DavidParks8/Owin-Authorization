using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationHelper : IResourceAuthorizationHelper
    {
        private readonly IOwinContextAccessor _owinContextAccessor;

        public AuthorizationHelper(IOwinContextAccessor owinContextAccessor)
        {
            if (owinContextAccessor == null)
            {
                throw new ArgumentNullException(nameof(owinContextAccessor));
            }

            _owinContextAccessor = owinContextAccessor;
        }

        public async Task<bool> IsAuthorizedAsync(IAuthorizationController controller, ClaimsPrincipal user, IAuthorizeData authorizeAttribute)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (authorizeAttribute == null)
            {
                throw new ArgumentNullException(nameof(authorizeAttribute));
            }

            AuthorizationOptions options;
            if (controller != null)
            {
                options = controller.AuthorizationOptions;
            }
            else
            {
                var owinContext = _owinContextAccessor.Context;
                var helper = new AuthorizationDependencyHelper(owinContext);
                options = helper.AuthorizationOptions;
            }
            
            if (options == null)
            {
                throw new InvalidOperationException("AuthorizationOptions must not be null.  Your resource authorization may be set up incorrectly.");
            }

            if (options.Dependencies == null)
            {
                throw new InvalidOperationException("AuthorizationOptions.Dependencies must not be null");
            }

            var authorizationService = options.Dependencies.Service;
            if (authorizationService == null)
            {
                authorizationService = CreateDefaultAuthorizationService(options);
            }

            var policy = AuthorizationPolicy.Combine(options, new[] {authorizeAttribute});
            return await authorizationService.AuthorizeAsync(user, policy);
        }

        private static IAuthorizationService CreateDefaultAuthorizationService(AuthorizationOptions options)
        {
            Debug.Assert(options != null, "options != null");
            Debug.Assert(options.Dependencies != null, "options.Dependencies != null");

            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var handlers = new HashSet<IAuthorizationHandler>(options.Dependencies.AdditionalHandlers)
            {
                new PassThroughAuthorizationHandler()
            };
            var logger = options.Dependencies.LoggerFactory?.Create("default");
            return new DefaultAuthorizationService(policyProvider, handlers, logger);
        }
    }
}

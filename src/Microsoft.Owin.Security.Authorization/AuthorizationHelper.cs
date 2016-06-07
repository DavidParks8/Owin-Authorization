using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
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

            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var authorizationService = GetAuthorizationService(options, policyProvider);
            var policy = await AuthorizationPolicy.CombineAsync(policyProvider, new[] { authorizeAttribute });
            return await authorizationService.AuthorizeAsync(user, policy);
        }

        private static IAuthorizationService GetAuthorizationService(AuthorizationOptions options, IAuthorizationPolicyProvider policyProvider)
        {
            Debug.Assert(options != null, "options != null");
            Debug.Assert(options.Dependencies != null, "options.Dependencies != null");

            if (options.Dependencies.Service != null)
            {
                return options.Dependencies.Service;
            }
            
            var handlers = new IAuthorizationHandler[] { new PassThroughAuthorizationHandler() };
            var logger = GetLogger(options);
            return new DefaultAuthorizationService(policyProvider, handlers, logger);
        }

        private static ILogger GetLogger(AuthorizationOptions options)
        {
            var loggerFactory = options.Dependencies.LoggerFactory ?? new DiagnosticsLoggerFactory();
            return loggerFactory.Create("ResourceAuthorization");
        }
    }
}

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.Properties;

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

            var options = ResolveAuthorizationOptions(controller);
            if (options == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthorizationOptionsMustNotBeNull);
            }

            if (options.DependenciesFactory == null)
            {
                throw new InvalidOperationException(Resources.Exception_AuthorizationDependenciesMustNotBeNull);
            }

            var dependencies = options.DependenciesFactory.Create(options, _owinContextAccessor.Context) 
                ?? new AuthorizationDependencies();

            var policyProvider = dependencies.PolicyProvider 
                ?? new DefaultAuthorizationPolicyProvider(options);
            var authorizationHandlers = dependencies.Handlers?.ToArray()
                ?? new IAuthorizationHandler[] { new PassThroughAuthorizationHandler() };
            var loggerFactory = dependencies.LoggerFactory
                ?? new DiagnosticsLoggerFactory();
            var serviceFactory = dependencies.ServiceFactory
                ?? new DefaultAuthorizationServiceFactory();
            
            var authorizationService = serviceFactory.Create(policyProvider, authorizationHandlers, loggerFactory);
            var policy = await AuthorizationPolicy.CombineAsync(policyProvider, new[] { authorizeAttribute });
            return await authorizationService.AuthorizeAsync(user, policy);
        }

        private AuthorizationOptions ResolveAuthorizationOptions(IAuthorizationController controller)
        {
            if (controller != null)
            {
                return controller.AuthorizationOptions;
            }

            var owinContext = _owinContextAccessor.Context;
            var helper = new AuthorizationDependencyHelper(owinContext);
            return helper.AuthorizationOptions;
        }
    }
}

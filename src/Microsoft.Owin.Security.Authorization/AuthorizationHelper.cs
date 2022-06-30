using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Infrastructure class which can authorize with or without owin.
    /// </summary>
    public class AuthorizationHelper : IResourceAuthorizationHelper
    {
        private readonly IOwinContextAccessor _owinContextAccessor;

        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationHelper"/>.
        /// </summary>
        /// <param name="owinContextAccessor"><see cref="IOwinContextAccessor"/> used to retrieve the <see cref="IOwinContext"/>.</param>
        public AuthorizationHelper(IOwinContextAccessor owinContextAccessor)
        {
            if (owinContextAccessor == null)
            {
                throw new ArgumentNullException(nameof(owinContextAccessor));
            }

            _owinContextAccessor = owinContextAccessor;
        }

        /// <summary>
        /// Determines if a user is authorized.
        /// </summary>
        /// <param name="controller">The controller from which <see cref="AuthorizationOptions"/> may be obtained.</param>
        /// <param name="user">The user to evaluate the authorize data against.</param>
        /// <param name="authorizeAttribute">The <see cref="IAuthorizeData"/> to evaluate.</param>
        /// <param name="resource">The resource to evaluate the authorize data against.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the <paramref name="user"/> fulfills the <paramref name="authorizeAttribute"/>; otherwise <value>false</value>.
        /// </returns>
        /// <remarks>
        /// If <paramref name="controller"/> is not null, it will be used to find <see cref="AuthorizationOptions"/> instead of the current <see cref="IOwinContext"/>.
        /// </remarks>
        public async Task<bool> IsAuthorizedAsync(IAuthorizationController controller, ClaimsPrincipal user, IAuthorizeData authorizeAttribute, object resource = null)
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

            var dependencies = options.Dependencies
                ?? new AuthorizationDependencies();
            var policyProvider = dependencies.PolicyProvider
                ?? new DefaultAuthorizationPolicyProvider(options);
            var authorizationService = dependencies.Service;
            if (authorizationService == null)
            {
                var handlerProvider = new DefaultAuthorizationHandlerProvider(new PassThroughAuthorizationHandler());
                var handlers = await handlerProvider.GetHandlersAsync();
                var loggerFactory = dependencies.LoggerFactory
                    ?? new DiagnosticsLoggerFactory();

                authorizationService = new DefaultAuthorizationService(
                    policyProvider,
                    handlers,
                    loggerFactory.CreateDefaultLogger(),
                    new DefaultAuthorizationHandlerContextFactory(),
                    new DefaultAuthorizationEvaluator());
            }

            var policy = await AuthorizationPolicy.CombineAsync(policyProvider, new[] { authorizeAttribute });
            return authorizationService.AuthorizeAsync(user, resource, policy);
        }

        private AuthorizationOptions ResolveAuthorizationOptions(IAuthorizationController controller)
        {
            if (controller != null)
            {
                return controller.AuthorizationOptions;
            }

            return _owinContextAccessor.Context.GetAuthorizationOptions();
        }
    }
}

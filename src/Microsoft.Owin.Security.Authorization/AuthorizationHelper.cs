using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.Properties;

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
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the <paramref name="user"/> fulfills the <paramref name="authorizeAttribute"/>; otherwise <value>false</value>.
        /// </returns>
        /// <remarks>
        /// If <paramref name="controller"/> is not null, it will be used to find <see cref="AuthorizationOptions"/> instead of the current <see cref="IOwinContext"/>.
        /// </remarks>
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

            var dependenciesFactory = options.DependenciesFactory
                ?? new DefaultAuthorizationDependenciesFactory();

            var dependencies = dependenciesFactory.Create(options, _owinContextAccessor.Context) 
                ?? new AuthorizationDependencies();

            var policyProvider = dependencies.PolicyProvider 
                ?? new DefaultAuthorizationPolicyProvider(options);
            var handlerProvider = dependencies.HandlerProvider 
                ?? new DefaultAuthorizationHandlerProvider(new PassThroughAuthorizationHandler());
            var loggerFactory = dependencies.LoggerFactory
                ?? new DiagnosticsLoggerFactory();
            var serviceFactory = dependencies.ServiceFactory
                ?? new DefaultAuthorizationServiceFactory();
            var contextFactory = dependencies.ContextFactory
                ?? new DefaultAuthorizationHandlerContextFactory();
            var evaluator = dependencies.Evaluator
                ?? new DefaultAuthorizationEvaluator();

            var handlers = await handlerProvider.GetHandlersAsync();
            var authorizationService = serviceFactory.Create(policyProvider, handlers, loggerFactory, contextFactory, evaluator)
                ?? new DefaultAuthorizationServiceFactory().Create(policyProvider, handlers, loggerFactory, contextFactory, evaluator);
            
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

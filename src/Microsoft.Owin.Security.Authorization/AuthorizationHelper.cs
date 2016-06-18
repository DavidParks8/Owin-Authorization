using System;
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

            IAuthorizationPolicyProvider policyProvider;
            IAuthorizationService service;
            if (controller != null)
            {
                var options = controller.AuthorizationOptions;
                if (options == null)
                {
                    throw new InvalidOperationException("AuthorizationOptions must not be null. Your resource authorization may be set up incorrectly.");
                }
                policyProvider = new DefaultAuthorizationPolicyProvider(options);
                service = new DefaultAuthorizationService(policyProvider, new IAuthorizationHandler[] {new PassThroughAuthorizationHandler()});
            }
            else
            {
                var owinContext = _owinContextAccessor.Context;
                var dependencies = owinContext.GetDependencies();
                if (dependencies == null)
                {
                    throw new InvalidOperationException(
                        "AuthorizationDependencies must not be null. Your resource authorization may be set up incorrectly.");
                }
                policyProvider = dependencies.PolicyProvider;
                service = dependencies.Service;
            }
            if (service == null)
            {
                throw new InvalidOperationException("AuthorizationService must not be null. Your resource authorization may be set up incorrectly.");
            }
            var policy = await AuthorizationPolicy.CombineAsync(policyProvider, new[] { authorizeAttribute });
            return await service.AuthorizeAsync(user, policy);
        }
    }
}

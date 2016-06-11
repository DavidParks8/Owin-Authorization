using System;
using System.Security.Claims;
using System.Threading.Tasks;

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

            AuthorizationDependencies dependencies;
            if (controller != null)
            {
                var dependenciesProvider = AuthorizationDependenciesProvider.CreateDefault();
                dependencies = dependenciesProvider.OnCreate?.Invoke(controller.AuthorizationOptions, null);
            }
            else
            {
                var owinContext = _owinContextAccessor.Context;
                dependencies = owinContext.GetDependencies();
            }

            if (dependencies == null)
            {
                throw new InvalidOperationException("AuthorizationDependencies must not be null.  Your resource authorization may be set up incorrectly.");
            }

            var policy = await AuthorizationPolicy.CombineAsync(dependencies.PolicyProvider, new[] { authorizeAttribute });
            return await dependencies.Service.AuthorizeAsync(user, policy);
        }
    }
}

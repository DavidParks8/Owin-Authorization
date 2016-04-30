using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationChecker
    {
        private readonly IAuthorizationService _authorizationService;
        private readonly IAuthorizationPolicyProvider _policyProvider;
        private readonly IAuthorizeData _authorizeData;

        public AuthorizationChecker(
            IAuthorizationService authorizationService,
            IAuthorizationPolicyProvider policyProvider, 
            IAuthorizeData authorizeData)
        {
            if (authorizationService == null)
            {
                throw new ArgumentNullException(nameof(authorizationService));
            }
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (authorizeData == null)
            {
                throw new ArgumentNullException(nameof(authorizeData));
            }

            _authorizationService = authorizationService;
            _policyProvider = policyProvider;
            _authorizeData = authorizeData;
        }

        public async Task<bool> IsAuthorizedAsync(ClaimsPrincipal user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var policyBuilder = new AuthorizationPolicyBuilder();

            if (!string.IsNullOrWhiteSpace(_authorizeData.Policy))
            {
                var policy = await _policyProvider.GetPolicyAsync(_authorizeData.Policy);
                policyBuilder.Combine(policy);
            }

            if (!string.IsNullOrWhiteSpace(_authorizeData.ActiveAuthenticationSchemes))
            {
                var schemes = _authorizeData.ActiveAuthenticationSchemes.Split(',');
                policyBuilder.AddAuthenticationSchemes(schemes);
            }

            var builtPolicy = policyBuilder.Build();
            return await _authorizationService.AuthorizeAsync(user, builtPolicy);
        }
    }
}

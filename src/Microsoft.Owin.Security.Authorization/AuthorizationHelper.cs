﻿using System;
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

        public async Task<bool> IsAuthorizedAsync(IAuthorizationHolder controller, ClaimsPrincipal user, IResourceAuthorize authorizeAttribute)
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
                throw new InvalidOperationException("No IAuthorizationService could be found");
            }

            return await authorizationService.AuthorizeAsync(user, authorizeAttribute, options);
        }
    }
}

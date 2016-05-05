using System;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationHelper
    {
        public AuthorizationOptions AuthorizationOptions { get; }

        public AuthorizationHelper(IOwinContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (context.Environment == null)
            {
                throw new ArgumentNullException(nameof(context), Resources.ErrorTheOwinEnvironmentDictionaryWasNull);
            }

            object environmentService;
            if (context.Environment.TryGetValue(ResourceAuthorizationMiddleware.ServiceKey, out environmentService))
            {
                AuthorizationOptions = (AuthorizationOptions) environmentService;
            }
            else
            {
                throw new InvalidOperationException(Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile);
            }
        }

        public bool ShouldUseDefaultPolicy(IAuthorizeData authorizeData)
        {
            if (authorizeData == null)
            {
                return true;
            }

            return string.IsNullOrWhiteSpace(authorizeData.Policy)
                   || string.IsNullOrWhiteSpace(authorizeData.Roles);
        }
    }
}
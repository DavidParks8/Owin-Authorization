using System;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationOwinHelper
    {
        public IAuthorizationService AuthorizationService { get; }

        public AuthorizationOwinHelper(IOwinContext context)
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
                AuthorizationService = (IAuthorizationService) environmentService;
            }
            else
            {
                throw new InvalidOperationException(Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile);
            }
        }
    }
}
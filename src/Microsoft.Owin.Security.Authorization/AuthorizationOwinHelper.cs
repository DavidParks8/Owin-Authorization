using System;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationOwinHelper
    {
        public IAuthorizationService AuthorizationService { get; }
        public IAuthorizationPolicyProvider PolicyProvider { get; }

        public AuthorizationOwinHelper(IOwinContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (context.Environment == null)
            {
                throw new ArgumentNullException(nameof(context),
                    Properties.Resources.ErrorTheOwinEnvironmentDictionaryWasNull);
            }

            object environmentService;
            object environmentPolicy;
            if (context.Environment.TryGetValue(ResourceAuthorizationMiddleware.ServiceKey, out environmentService)
                && context.Environment.TryGetValue(ResourceAuthorizationMiddleware.PolicyKey, out environmentPolicy))
            {
                AuthorizationService = (IAuthorizationService) environmentService;
                PolicyProvider = (IAuthorizationPolicyProvider) environmentPolicy;
            }
            else
            {
                throw new InvalidOperationException(Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile);
            }
        }
    }
}
using System;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Extracts authorization objects from an <see cref="IOwinContext"/> environment.
    /// </summary>
    public static class OwinContextExtensions
    {
        /// <summary>
        /// Extracts an <see cref="AuthorizationOptions"/> from the <see cref="IOwinContext"/>.
        /// </summary>
        public static AuthorizationOptions GetAuthorizationOptions(this IOwinContext context)
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
                if (environmentService == null)
                {
                    throw new InvalidOperationException(Resources.Exception_AuthorizationOptionsMustNotBeNull);
                }
  
                return (AuthorizationOptions)environmentService;
            }

            throw new InvalidOperationException(Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile);
        }

        /// <summary>
        /// Extracts an <see cref="IAuthorizationService"/> from the <see cref="IOwinContext"/>.
        /// </summary>
        public static IAuthorizationService GetAuthorizationService(this IOwinContext context)
        {
            return GetAuthorizationOptions(context).Dependencies?.Service;
        }
    }
}
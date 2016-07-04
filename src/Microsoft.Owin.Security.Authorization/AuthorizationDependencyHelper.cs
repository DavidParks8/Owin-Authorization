using System;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Extracts authorization objects from an <see cref="IOwinContext"/> environment.
    /// </summary>
    internal class AuthorizationDependencyHelper
    {
        /// <summary>
        /// The <see cref="AuthorizationOptions"/> which were extracted from the <see cref="IOwinContext"/>.
        /// </summary>
        public AuthorizationOptions AuthorizationOptions { get; }

        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationDependencyHelper"/>.
        /// </summary>
        /// <param name="context"><see cref="IOwinContext"/> that is used to extract <see cref="AuthorizationOptions"/>.</param>
        public AuthorizationDependencyHelper(IOwinContext context)
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
                AuthorizationOptions = (AuthorizationOptions)environmentService;
            }
            else
            {
                throw new InvalidOperationException(Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile);
            }
        }
    }
}
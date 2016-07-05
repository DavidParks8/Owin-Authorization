using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationDependencies"/>.
    /// </summary>
    public class AuthorizationDependencies : IAuthorizationDependencies
    {
        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationServiceFactory"/>.
        /// </summary>
        public IAuthorizationServiceFactory ServiceFactory { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="ILoggerFactory"/>.
        /// </summary>
        public ILoggerFactory LoggerFactory { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationPolicyProvider"/>.
        /// </summary>
        public IAuthorizationPolicyProvider PolicyProvider { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationHandlerProvider"/>.
        /// </summary>
        public IAuthorizationHandlerProvider HandlerProvider { get; set; }
    }
}
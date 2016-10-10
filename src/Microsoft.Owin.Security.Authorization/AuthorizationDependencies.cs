using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationDependencies"/>.
    /// </summary>
    public class AuthorizationDependencies : IAuthorizationDependencies
    {
        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationService"/>.
        /// </summary>
        public virtual IAuthorizationService Service { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="ILoggerFactory"/>.
        /// </summary>
        public virtual ILoggerFactory LoggerFactory { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationPolicyProvider"/>.
        /// </summary>
        public virtual IAuthorizationPolicyProvider PolicyProvider { get; set; }
    }
}
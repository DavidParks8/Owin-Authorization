using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Types which implement <see cref="IAuthorizationDependencies"/> will be able to control the lifetime of the various types authorization depends upon.
    /// </summary>
    public interface IAuthorizationDependencies
    {
        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationService"/>.
        /// </summary>
        IAuthorizationService Service { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="ILoggerFactory"/>.
        /// </summary>
        ILoggerFactory LoggerFactory { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationPolicyProvider"/>.
        /// </summary>
        IAuthorizationPolicyProvider PolicyProvider { get; set; }
    }
}
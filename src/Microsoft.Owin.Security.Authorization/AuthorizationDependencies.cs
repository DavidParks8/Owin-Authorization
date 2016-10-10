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
        public virtual IAuthorizationServiceFactory ServiceFactory { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="ILoggerFactory"/>.
        /// </summary>
        public virtual ILoggerFactory LoggerFactory { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationPolicyProvider"/>.
        /// </summary>
        public virtual IAuthorizationPolicyProvider PolicyProvider { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationHandlerProvider"/>.
        /// </summary>
        public virtual IAuthorizationHandlerProvider HandlerProvider { get; set; }

        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationHandlerContextFactory"/>.
        /// </summary>
        public virtual IAuthorizationHandlerContextFactory ContextFactory { get; set; }
        
        /// <summary>
        /// Gets or sets an <see cref="IAuthorizationEvaluator"/>.
        /// </summary>
        public virtual IAuthorizationEvaluator Evaluator { get; set; }
    }
}
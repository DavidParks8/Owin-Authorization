using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationDependencies"/>.
    /// </summary>
    public class AuthorizationDependencies : IAuthorizationDependencies
    {
        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationDependencies"/>.
        /// </summary>
        /// <param name="options">The options used to configure the dependencies instance.</param>
        /// <param name="handlers">The <see cref="IAuthorizationHandler"/>s used in creating an <see cref="IAuthorizationDependencies"/> object.</param>
        public static AuthorizationDependencies Create(AuthorizationOptions options, params IAuthorizationHandler[] handlers)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var loggerFactory = new DiagnosticsLoggerFactory();
            var service = new DefaultAuthorizationService(
                policyProvider,
                handlers,
                loggerFactory.CreateDefaultLogger(),
                new DefaultAuthorizationHandlerContextFactory(),
                new DefaultAuthorizationEvaluator());

            return new AuthorizationDependencies()
            {
                LoggerFactory = loggerFactory,
                PolicyProvider = policyProvider,
                Service = service
            };
        }
      
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
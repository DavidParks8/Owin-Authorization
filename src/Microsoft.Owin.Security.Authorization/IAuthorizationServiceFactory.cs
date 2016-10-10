using System.Collections.Generic;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// A type which can provide an <see cref="IAuthorizationService"/> for a particular set of arguments.
    /// </summary>
    public interface IAuthorizationServiceFactory
    {
        /// <summary>
        /// Allows lifetime control for the creation of new <see cref="IAuthorizationService"/>s.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> for providing policies.</param>
        /// <param name="authorizationHandlers">A set <see cref="IAuthorizationHandler"/>s for evaluating authorization.</param>
        /// <param name="loggerFactory">An <see cref="ILoggerFactory"/> for logging.</param>
        /// <param name="contextFactory">The <see cref="IAuthorizationHandlerContextFactory"/> used to create the context to handle the authorization.</param>
        /// <param name="evaluator"></param>
        IAuthorizationService Create(
            IAuthorizationPolicyProvider policyProvider,
            IEnumerable<IAuthorizationHandler> authorizationHandlers,
            ILoggerFactory loggerFactory,
            IAuthorizationHandlerContextFactory contextFactory,
            IAuthorizationEvaluator evaluator);
    }
}
namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Determines whether an authorization request was successful or not.
    /// </summary>
    public class DefaultAuthorizationEvaluator : IAuthorizationEvaluator
    {
        /// <summary>
        /// Returns true, if authorization has failed.
        /// </summary>
        /// <param name="context">The authorization information.</param>
        /// <returns>True if authorization has failed.</returns>
        public virtual bool HasFailed(AuthorizationHandlerContext context)
        {
            return context.HasFailed;
        }

        /// <summary>
        /// Returns true, if authorization has succeeded.
        /// </summary>
        /// <param name="context">The authorization information.</param>
        /// <returns>True if authorization has succeeded.</returns>
        public virtual bool HasSucceeded(AuthorizationHandlerContext context)
        {
            return context.HasSucceeded;
        }
    }
}
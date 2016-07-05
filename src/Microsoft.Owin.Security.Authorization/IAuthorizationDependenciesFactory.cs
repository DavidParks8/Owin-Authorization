namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// A type which can provide an <see cref="IAuthorizationDependencies"/>.
    /// </summary>
    public interface IAuthorizationDependenciesFactory
    {
        /// <summary>
        /// Creates an <see cref="IAuthorizationDependencies"/> from the given <paramref name="options"/> and <paramref name="owinContext"/>.
        /// </summary>
        /// <param name="options">The <see cref="AuthorizationOptions"/> to use during <see cref="IAuthorizationDependencies"/> creation.</param>
        /// <param name="owinContext">The <see cref="IOwinContext"/> to use during <see cref="IAuthorizationDependencies"/> creation.</param>
        /// <returns>The <see cref="IAuthorizationDependencies"/> instance.</returns>
        IAuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext);
    }
}
namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Provides access to an <see cref="IOwinContext"/>
    /// </summary>
    public interface IOwinContextAccessor
    {
        /// <summary>
        /// Gets an <see cref="IOwinContext"/>.
        /// </summary>
        IOwinContext Context { get; }
    }
}

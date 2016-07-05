using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// A type which provides access to a set of <see cref="IAuthorizationHandler"/>s.
    /// </summary>
    public interface IAuthorizationHandlerProvider
    {
        /// <summary>
        /// Retrieves an enumeration of <see cref="IAuthorizationHandler"/>s which should be used to evaluate authorization.
        /// </summary>
        /// <returns>An <see cref="IEnumerable{IAuthorizationHandler}"/> for use in deciding if authorization is allowed.</returns>
        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = "This could be a time consuming action")]
        Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync();
    }
}
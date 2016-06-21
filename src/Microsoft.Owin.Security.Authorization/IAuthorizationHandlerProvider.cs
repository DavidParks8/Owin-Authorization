using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationHandlerProvider
    {
        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = "This could be a time consuming action")]
        Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync();
    }
}
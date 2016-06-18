using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationHandlerProvider
    {
        Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync();
    }
}
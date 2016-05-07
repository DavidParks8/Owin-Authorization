using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IResourceAuthorizationHelper
    {
        Task<bool> IsAuthorizedAsync(IAuthorizationHolder controller, ClaimsPrincipal user, IResourceAuthorize authorizeAttribute);
    }
}
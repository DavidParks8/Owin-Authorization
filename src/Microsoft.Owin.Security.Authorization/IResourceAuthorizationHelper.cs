using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Classes implementing this interface are able to authorize with or without owin.
    /// </summary>
    public interface IResourceAuthorizationHelper
    {
        /// <summary>
        /// Determines if a user is authorized.
        /// </summary>
        /// <param name="controller">The controller from which <see cref="AuthorizationOptions"/> may be obtained.</param>
        /// <param name="user">The user to evaluate the authorize data against.</param>
        /// <param name="authorizeAttribute">The <see cref="IAuthorizeData"/> to evaluate.</param>
        /// <param name="resource">The resource to evaluate the authorize data against.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the <paramref name="user"/> fulfills the <paramref name="authorizeAttribute"/>; otherwise <value>false</value>.
        /// </returns>
        Task<bool> IsAuthorizedAsync(IAuthorizationController controller, ClaimsPrincipal user, IAuthorizeData authorizeAttribute, object resource = null);
    }
}

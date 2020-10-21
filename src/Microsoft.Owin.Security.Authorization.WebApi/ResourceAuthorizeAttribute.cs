using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Controllers;

namespace Microsoft.Owin.Security.Authorization.WebApi
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1813:AvoidUnsealedAttributes", Justification = "It must remain extensible")]
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : System.Web.Http.AuthorizeAttribute, IAuthorizeData
    {
        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        /// <inheritdoc />
        public override async Task OnAuthorizationAsync(HttpActionContext actionContext, CancellationToken cancellationToken)
        {
            if (actionContext == null)
            {
                throw new ArgumentNullException(nameof(actionContext));
            }

            await base.OnAuthorizationAsync(actionContext, cancellationToken);
            if (actionContext.Response != null) return;

            var controller = actionContext.ControllerContext.Controller as IAuthorizationController;
            var user = (ClaimsPrincipal)actionContext.RequestContext.Principal;
            var owinAccessor = new HttpRequestMessageOwinContextAccessor(actionContext.Request);
            var helper = new AuthorizationHelper(owinAccessor);
            if (!await helper.IsAuthorizedAsync(controller, user, this, actionContext))
            {
                HandleUnauthorizedRequest(actionContext);
            }
        }
    }
}

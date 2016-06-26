using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1813:AvoidUnsealedAttributes", Justification = "It must remain extensible")]
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : AuthorizeAttribute, IAuthorizeData
    {
        private const string s_controllerKey = "Owin.AuthorizationController";

        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        public override void OnAuthorization(System.Web.Mvc.AuthorizationContext filterContext)
        {
            if (filterContext == null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            //todo: handle items being null
            filterContext.HttpContext.Items.Add(s_controllerKey, filterContext.Controller);
            base.OnAuthorization(filterContext);
        }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException(nameof(httpContext));
            }

            var controller = httpContext.Items[s_controllerKey] as IAuthorizationController;
            var user = (ClaimsPrincipal)httpContext.User;
            var contextAccessor = new HttpContextBaseOwinContextAccessor(httpContext);
            var authorizationHelper = new AuthorizationHelper(contextAccessor);
            return authorizationHelper.IsAuthorizedAsync(controller, user, this).Result;
        }
    }
}

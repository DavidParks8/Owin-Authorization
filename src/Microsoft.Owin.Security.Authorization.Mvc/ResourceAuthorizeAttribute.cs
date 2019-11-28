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
        private const string s_authorizationContextKey = "Owin.AuthorizationContext";

        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        /// <inheritdoc />
        public override void OnAuthorization(System.Web.Mvc.AuthorizationContext filterContext)
        {
            if (filterContext == null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            if (!filterContext.HttpContext.Items.Contains(s_authorizationContextKey))
            {
                filterContext.HttpContext.Items.Add(s_authorizationContextKey, filterContext);
            }

            base.OnAuthorization(filterContext);
        }

        /// <inheritdoc />
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException(nameof(httpContext));
            }

            var filterContext = httpContext.Items[s_authorizationContextKey] as System.Web.Mvc.AuthorizationContext;
            var controller = filterContext?.Controller as IAuthorizationController;
            var user = (ClaimsPrincipal)httpContext.User;
            var contextAccessor = new HttpContextBaseOwinContextAccessor(httpContext);
            var authorizationHelper = new AuthorizationHelper(contextAccessor);
            return authorizationHelper.IsAuthorizedAsync(controller, user, this, filterContext).Result;
        }
    }
}

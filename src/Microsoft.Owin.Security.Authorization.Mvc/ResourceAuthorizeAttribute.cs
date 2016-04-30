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
    public class ResourceAuthorizeAttribute : AuthorizeAttribute, IResourceAuthorize
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        public ResourceAuthorizeAttribute() { }

        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        /// <inheritdoc />
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
            {
                throw new ArgumentNullException(nameof(httpContext));
            }

            var owinContext = httpContext.GetOwinContext();
            var helper = new AuthorizationOwinHelper(owinContext);
            var checker = new AuthorizationChecker(helper.AuthorizationService, helper.PolicyProvider, this);
            return checker.IsAuthorizedAsync((ClaimsPrincipal) httpContext.User).Result;
        }
    }
}

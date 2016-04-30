using System;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : AuthorizeAttribute, IResourceAuthorize
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        public ResourceAuthorizeAttribute() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class with the specified policy. 
        /// </summary>
        /// <param name="policy">The name of the policy to require for authorization.</param>
        public ResourceAuthorizeAttribute(string policy)
        {
            Policy = policy;
        }

        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            var owinContext = httpContext.GetOwinContext();
            var helper = new AuthorizationOwinHelper(owinContext);
            var checker = new AuthorizationChecker(helper.AuthorizationService, helper.PolicyProvider, this);
            return checker.IsAuthorizedAsync((ClaimsPrincipal) httpContext.User).Result;
        }
    }
}

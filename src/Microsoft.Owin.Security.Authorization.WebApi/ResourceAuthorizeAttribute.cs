using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Web.Http.Controllers;

namespace Microsoft.Owin.Security.Authorization.WebApi
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1813:AvoidUnsealedAttributes", Justification = "It must remain extensible")]
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : System.Web.Http.AuthorizeAttribute, IResourceAuthorize
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
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (actionContext == null)
            {
                throw new ArgumentNullException(nameof(actionContext));
            }

            var owinContext = actionContext.Request.GetOwinContext();
            var helper = new AuthorizationHelper(owinContext);
            var service = helper.AuthorizationOptions.Dependencies.Service;
            return service.AuthorizeAsync(owinContext.Authentication.User, this, helper.AuthorizationOptions).Result;
        }
    }
}

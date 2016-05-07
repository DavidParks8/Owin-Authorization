using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Web.Mvc;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1813:AvoidUnsealedAttributes", Justification = "It must remain extensible")]
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : FilterAttribute, IResourceAuthorize , IAuthorizationFilter
    {
        private readonly IOwinContextAccessor m_contextAccessor;

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        public ResourceAuthorizeAttribute() : this(new OwinContextAccessor()) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        /// <param name="contextAccessor">Allows easily testable retrieval of an <see cref="IOwinContext"/></param>
        public ResourceAuthorizeAttribute(IOwinContextAccessor contextAccessor)
        {
            if (contextAccessor == null)
            {
                throw new ArgumentNullException(nameof(contextAccessor));
            }

            m_contextAccessor = contextAccessor;
        }

        /// <inheritdoc />
        public string Policy { get; set; }

        /// <inheritdoc />
        public string Roles { get; set; }

        /// <inheritdoc />
        public string ActiveAuthenticationSchemes { get; set; }

        public void OnAuthorization(System.Web.Mvc.AuthorizationContext filterContext)
        {
            if (filterContext == null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            AuthorizationOptions options;
            var httpContext = filterContext.HttpContext;
            var controller = filterContext.Controller as IAuthorizationHolder;
            if (controller != null)
            {
                options = controller.AuthorizationOptions;
            }
            else
            {
                var owinContext = m_contextAccessor.GetOwinContext(httpContext);
                var helper = new AuthorizationHelper(owinContext);
                options = helper.AuthorizationOptions;
            }

            if (options == null)
            {
                throw new InvalidOperationException("AuthorizationOptions must not be null.  Your resource authorization may be set up incorrectly.");
            }

            if (options.Dependencies == null)
            {
                throw new InvalidOperationException("AuthorizationOptions.Dependencies must not be null");
            }

            var authorizationService = options.Dependencies.Service;
            if (authorizationService == null)
            {
                throw new InvalidOperationException("No IAuthorizationService could be found");
            }

            var user = (ClaimsPrincipal) httpContext.User;
            if (!authorizationService.AuthorizeAsync(user, this, options).Result)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }
    }
}

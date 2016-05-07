﻿using System;
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
        private readonly  IResourceAuthorizationHelper _authorizationHelper;

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        public ResourceAuthorizeAttribute() : this(new AuthorizationHelper(new OwinContextAccessor(new HttpContextAccessor()))) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceAuthorizeAttribute"/> class. 
        /// </summary>
        public ResourceAuthorizeAttribute(IResourceAuthorizationHelper authorizationHelper)
        {
            if (authorizationHelper == null)
            {
                throw new ArgumentNullException(nameof(authorizationHelper));
            }

            _authorizationHelper = authorizationHelper;
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

            var controller = filterContext.Controller as IAuthorizationHolder;
            var user = (ClaimsPrincipal) filterContext.HttpContext.User;
            if (!_authorizationHelper.IsAuthorizedAsync(controller, user, this).Result)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }
    }
}

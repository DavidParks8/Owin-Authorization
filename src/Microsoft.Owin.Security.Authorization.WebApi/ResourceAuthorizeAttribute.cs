﻿using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Claims;
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
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (actionContext == null)
            {
                throw new ArgumentNullException(nameof(actionContext));
            }

            var controller = actionContext.ControllerContext.Controller as IAuthorizationController;
            var user = (ClaimsPrincipal)actionContext.RequestContext.Principal;
            return new AuthorizationHelper(new HttpRequestMessageOwinContextAccessor(actionContext.Request)).IsAuthorizedAsync(controller, user, this).Result;
        }
    }
}

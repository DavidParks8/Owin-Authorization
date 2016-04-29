// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Specifies that the class or method that this attribute is applied to requires the specified authorization.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ResourceAuthorizeAttribute : AuthorizeAttribute, IAuthorizeData
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
            object environmentService;
            object environmentPolicy;
            if (owinContext.Environment.TryGetValue(ResourceAuthorizationMiddleware.ServiceKey, out environmentService)
                && owinContext.Environment.TryGetValue(ResourceAuthorizationMiddleware.PolicyKey, out environmentPolicy))
            {
                var service = (IAuthorizationService) environmentService;
                var policyProvider = (IAuthorizationPolicyProvider) environmentPolicy;
                var user = (ClaimsPrincipal) httpContext.User;
                var policyBuilder = new AuthorizationPolicyBuilder();

                if (!string.IsNullOrWhiteSpace(Policy))
                {
                    var policy = policyProvider.GetPolicyAsync(Policy).Result;
                    policyBuilder.Combine(policy);
                }

                if (!string.IsNullOrWhiteSpace(ActiveAuthenticationSchemes))
                {
                    var schemes = ActiveAuthenticationSchemes.Split(',');
                    policyBuilder.AddAuthenticationSchemes(schemes);
                }

                var builtPolicy = policyBuilder.Build();
                return service.AuthorizeAsync(user, builtPolicy).Result;
            }

            return base.AuthorizeCore(httpContext);
        }
    }
}

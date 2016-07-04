// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    /// <summary>
    /// Implements an <see cref="IAuthorizationHandler"/> and <see cref="IAuthorizationRequirement"/>
    /// which requires the current user name must match the specified value.
    /// </summary>
    public class NameAuthorizationRequirement : AuthorizationHandler<NameAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Gets the required name that the current user must have.
        /// </summary>
        public string RequiredName { get; }

        /// <summary>
        /// Constructs a new instance of <see cref="NameAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="requiredName">The required name that the current user must have.</param>
        public NameAuthorizationRequirement(string requiredName)
        {
            if (requiredName == null)
            {
                throw new ArgumentNullException(nameof(requiredName));
            }

            RequiredName = requiredName;
        }

        /// <summary>
        /// Makes a decision if authorization is allowed based on a specific requirement.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NameAuthorizationRequirement requirement)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (requirement == null)
            {
                throw new ArgumentNullException(nameof(requirement));
            }

            if (context.User != null)
            {
                var identities = context.User.Identities;
                foreach (var identity in identities)
                {
                    if (ContainsRequiredName(identity, requirement))
                    {
                        context.Succeed(requirement);
                        break;
                    }
                }
            }

            return Task.FromResult(0);
        }

        private static bool ContainsRequiredName(ClaimsIdentity identity, NameAuthorizationRequirement requirement)
        {
            Debug.Assert(identity != null, "identity != null");
            Debug.Assert(requirement != null, "requirement != null");

            return string.Equals(identity.Name, requirement.RequiredName, StringComparison.OrdinalIgnoreCase);
        }
    }
}

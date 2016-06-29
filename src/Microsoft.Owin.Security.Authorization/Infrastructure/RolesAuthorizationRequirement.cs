// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Authorization.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    /// <summary>
    /// Requires the user to belong to atleast one of the roles specified in <see cref="AllowedRoles"/>
    /// </summary>
    public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
    {
        public IEnumerable<string> AllowedRoles { get; }

        public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
        {
            if (allowedRoles == null)
            {
                throw new ArgumentNullException(nameof(allowedRoles));
            }

            // ReSharper disable once PossibleMultipleEnumeration because it will not enumerate the entire list
            if (!allowedRoles.Any())
            {
                throw new InvalidOperationException(Resources.Exception_RoleRequirementEmpty);
            }

            // ReSharper disable once PossibleMultipleEnumeration
            AllowedRoles = allowedRoles;
        }

        protected override void Handle(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (requirement == null)
            {
                throw new ArgumentNullException(nameof(requirement));
            }

            if (context.User == null)
            {
                return;
            }

            Debug.Assert(requirement.AllowedRoles != null, "requirement.AllowedRoles != null");
            Debug.Assert(requirement.AllowedRoles.Any(), "requirement.AllowedRoles.Any()");

            var found = requirement.AllowedRoles.Any(role => context.User.IsInRole(role));
            if (found)
            {
                context.Succeed(requirement);
            }
        }
    }
}

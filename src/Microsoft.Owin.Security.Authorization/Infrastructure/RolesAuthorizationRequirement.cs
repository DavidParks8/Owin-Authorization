// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Authorization.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    // Must belong to with one of specified roles
    public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
    {
        public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
        {
            if (allowedRoles == null)
            {
                throw new ArgumentNullException(nameof(allowedRoles));
            }

            if (!allowedRoles.Any())
            {
                throw new InvalidOperationException(Resources.Exception_RoleRequirementEmpty);
            }

            AllowedRoles = allowedRoles;
        }

        public IEnumerable<string> AllowedRoles { get; }

        protected override void Handle(AuthorizationContext context, RolesAuthorizationRequirement requirement)
        {

            if (context == null)
            {
                // Review: see how error preprocessor directive can be used to enforce best practices
                //#if DEBUG
                //#error context is null
                //#endif
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

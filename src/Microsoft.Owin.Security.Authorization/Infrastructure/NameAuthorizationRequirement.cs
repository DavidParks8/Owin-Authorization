// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Claims;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    /// <summary>
    /// Requirement that ensures a specific Name using a case insensitive comparison
    /// </summary>
    public class NameAuthorizationRequirement : AuthorizationHandler<NameAuthorizationRequirement>, IAuthorizationRequirement
    {
        public NameAuthorizationRequirement(string requiredName)
        {
            if (requiredName == null)
            {
                throw new ArgumentNullException(nameof(requiredName));
            }

            RequiredName = requiredName;
        }

        public string RequiredName { get; }

        protected override void Handle(AuthorizationContext context, NameAuthorizationRequirement requirement)
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

        private static bool ContainsRequiredName(ClaimsIdentity identity, NameAuthorizationRequirement requirement)
        {
            Debug.Assert(identity != null, "identity != null");
            Debug.Assert(requirement != null, "requirement != null");

            return string.Equals(identity.Name, requirement.RequiredName, StringComparison.OrdinalIgnoreCase);
        }
    }
}

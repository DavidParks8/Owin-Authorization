// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    /// <summary>
    /// Requires that the user must contain a claim with the specified name, and at least one of the required values.
    /// If <see cref="AllowedValues"/> is null or empty, that means any claim is valid.
    /// </summary>
    public class ClaimsAuthorizationRequirement : AuthorizationHandler<ClaimsAuthorizationRequirement>, IAuthorizationRequirement
    {
        public string ClaimType { get; }
        public IEnumerable<string> AllowedValues { get; }

        public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string> allowedValues)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            ClaimType = claimType;
            AllowedValues = allowedValues;
        }

        protected override void Handle(AuthorizationContext context, ClaimsAuthorizationRequirement requirement)
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

            bool found;
            if (requirement.AllowedValues == null || !requirement.AllowedValues.Any())
            {
                found = context.User.Claims.Any(c => string.Equals(c.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                found = false;
                foreach (var claim in context.User.Claims)
                {
                    if (string.Equals(claim.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase))
                    {
                        if (requirement.AllowedValues.Contains(claim.Value, StringComparer.Ordinal))
                        {
                            found = true;
                            break;
                        }
                    }
                }
            }

            if (found)
            {
                context.Succeed(requirement);
            }
        }
    }
}

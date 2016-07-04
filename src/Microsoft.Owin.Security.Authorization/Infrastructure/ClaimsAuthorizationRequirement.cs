// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    /// <summary>
    /// Implements an <see cref="IAuthorizationHandler"/> and <see cref="IAuthorizationRequirement"/>
    /// which requires at least one instance of the specified claim type, and, if allowed values are specified, 
    /// the claim value must be any of the allowed values.
    /// </summary>
    /// <remarks>
    /// If <see cref="AllowedValues"/> is null or empty, that means any claim is valid.
    /// </remarks>
    public class ClaimsAuthorizationRequirement : AuthorizationHandler<ClaimsAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Gets the claim type that must be present.
        /// </summary>
        public string ClaimType { get; }

        /// <summary>
        /// Gets the optional list of claim values, which, if present, 
        /// the claim must match.
        /// </summary>
        public IEnumerable<string> AllowedValues { get; }

        /// <summary>
        /// Creates a new instance of <see cref="ClaimsAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="claimType">The claim type that must be present.</param>
        /// <param name="allowedValues">The optional list of claim values, which, if present, 
        /// the claim must match.</param>
        public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string> allowedValues)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            ClaimType = claimType;
            AllowedValues = allowedValues;
        }

        /// <summary>
        /// Makes a decision if authorization is allowed based on the claims requirements specified.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
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
                bool found;
                if (requirement.AllowedValues == null || !requirement.AllowedValues.Any())
                {
                    found =
                        context.User.Claims.Any(
                            c => string.Equals(c.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase));
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

            return Task.FromResult(0);
        }
    }
}

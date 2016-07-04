// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Authorization.Properties;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Represents a collection of authorization requirements and the scheme or 
    /// schemes they are evaluated against, all of which must succeed
    /// for authorization to succeed.
    /// </summary>
    public class AuthorizationPolicy
    {
        /// <summary>
        /// Gets a readonly list of <see cref="IAuthorizationRequirement"/>s which must succeed for
        /// this policy to be successful.
        /// </summary>
        public IReadOnlyList<IAuthorizationRequirement> Requirements { get; }

        /// <summary>
        /// Gets a readonly list of the authentication schemes the <see cref="AuthorizationPolicy.Requirements"/> 
        /// are evaluated against.
        /// </summary>
        public IReadOnlyList<string> AuthenticationSchemes { get; }

        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationPolicy"/>.
        /// </summary>
        /// <param name="requirements">
        /// The list of <see cref="IAuthorizationRequirement"/>s which must succeed for
        /// this policy to be successful.
        /// </param>
        /// <param name="authenticationSchemes">
        /// The authentication schemes the <paramref name="requirements"/> are evaluated against.
        /// </param>
        public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements, IEnumerable<string> authenticationSchemes)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            if (authenticationSchemes == null)
            {
                throw new ArgumentNullException(nameof(authenticationSchemes));
            }

            var requirementsList = new List<IAuthorizationRequirement>(requirements);
            if (requirementsList.Count == 0)
            {
                throw new InvalidOperationException(Resources.Exception_AuthorizationPolicyEmpty);
            }
            Requirements = requirementsList.AsReadOnly();
            AuthenticationSchemes = new List<string>(authenticationSchemes).AsReadOnly();
        }

        /// <summary>
        /// Combines the specified <see cref="AuthorizationPolicy"/> into a single policy.
        /// </summary>
        /// <param name="policies">The authorization policies to combine.</param>
        /// <returns>
        /// A new <see cref="AuthorizationPolicy"/> which represents the combination of the
        /// specified <paramref name="policies"/>.
        /// </returns>
        public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
        {
            if (policies == null)
            {
                throw new ArgumentNullException(nameof(policies));
            }

            return Combine((IEnumerable<AuthorizationPolicy>)policies);
        }

        /// <summary>
        /// Combines the specified <see cref="AuthorizationPolicy"/> into a single policy.
        /// </summary>
        /// <param name="policies">The authorization policies to combine.</param>
        /// <returns>
        /// A new <see cref="AuthorizationPolicy"/> which represents the combination of the
        /// specified <paramref name="policies"/>.
        /// </returns>
        public static AuthorizationPolicy Combine(IEnumerable<AuthorizationPolicy> policies)
        {
            if (policies == null)
            {
                throw new ArgumentNullException(nameof(policies));
            }

            var builder = new AuthorizationPolicyBuilder();
            foreach (var policy in policies)
            {
                builder.Combine(policy);
            }
            return builder.Build();
        }

        /// <summary>
        /// Combines the <see cref="AuthorizationPolicy"/> provided by the specified
        /// <paramref name="policyProvider"/>.
        /// </summary>
        /// <param name="policyProvider">A <see cref="IAuthorizationPolicyProvider"/> which provides the policies to combine.</param>
        /// <param name="authorizeData">A collection of authorization data used to apply authorization to a resource.</param>
        /// <returns>
        /// A new <see cref="AuthorizationPolicy"/> which represents the combination of the
        /// authorization policies provided by the specified <paramref name="policyProvider"/>.
        /// </returns>
        public static async Task<AuthorizationPolicy> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }

            if (authorizeData == null)
            {
                throw new ArgumentNullException(nameof(authorizeData));
            }

            var policyBuilder = new AuthorizationPolicyBuilder();
            var any = false;
            foreach (var authorizeAttribute in authorizeData)
            {
                any = true;
                var useDefaultPolicy = true;
                if (!string.IsNullOrWhiteSpace(authorizeAttribute.Policy))
                {
                    var policy = await policyProvider.GetPolicyAsync(authorizeAttribute.Policy);
                    if (policy == null)
                    {
                        throw new InvalidOperationException(ResourceHelper.FormatException_AuthorizationPolicyNotFound(authorizeAttribute.Policy));
                    }

                    policyBuilder.Combine(policy);
                    useDefaultPolicy = false;
                }

                if (!string.IsNullOrWhiteSpace(authorizeAttribute.Roles))
                {
                    policyBuilder.RequireRole(SplitAndTrim(authorizeAttribute.Roles));
                    useDefaultPolicy = false;
                }

                if (!string.IsNullOrWhiteSpace(authorizeAttribute.ActiveAuthenticationSchemes))
                {
                    policyBuilder.AddAuthenticationSchemes(SplitAndTrim(authorizeAttribute.ActiveAuthenticationSchemes));
                    useDefaultPolicy = false;
                }

                if (useDefaultPolicy)
                {
                    policyBuilder.Combine(await policyProvider.GetDefaultPolicyAsync());
                }
            }

            if (any)
            {
                if (policyBuilder.AuthenticationSchemes.Count > 0)
                {
                    if (policyBuilder.Requirements.Count == 0)
                    {
                        policyBuilder.RequireAuthenticatedUser();
                    }
                }

                return policyBuilder.Build();
            }

            return null;
        }

        private static string[] SplitAndTrim(string commaSeparated)
        {
            var split = commaSeparated.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < split.Length; i++)
            {
                split[i] = split[i].Trim();
            }

            return split;
        }
    }
}
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin.Security.Authorization.Properties;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class AuthorizationPolicy
    {
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

        public IReadOnlyList<IAuthorizationRequirement> Requirements { get; }
        public IReadOnlyList<string> AuthenticationSchemes { get; }

        public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
        {
            if (policies == null)
            {
                throw new ArgumentNullException(nameof(policies));
            }

            return Combine((IEnumerable<AuthorizationPolicy>)policies);
        }

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

        public static async Task<AuthorizationPolicy> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> attributes)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }

            if (attributes == null)
            {
                throw new ArgumentNullException(nameof(attributes));
            }
            
            var policyBuilder = new AuthorizationPolicyBuilder();
            var any = false;
            foreach (var authorizeAttribute in attributes)
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
            var split = commaSeparated.Split(new [] {','}, StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < split.Length; i++)
            {
                split[i] = split[i].Trim();
            }

            return split;
        }
    }
}
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// A type which can provide a <see cref="AuthorizationPolicy"/> for a particular name.
    /// </summary>
    public class DefaultAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;

        public DefaultAuthorizationPolicyProvider(AuthorizationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options;
        } 

        /// <summary>
        /// Gets a <see cref="AuthorizationPolicy"/> from the given <paramref name="policyName"/>
        /// </summary>
        /// <param name="policyName"></param>
        /// <returns></returns>
        public virtual async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (_options.Dependencies?.PolicyProvider != null)
            {
                return await _options.Dependencies.PolicyProvider.GetPolicyAsync(policyName);
            }

            return _options.GetPolicy(policyName);
        }

        /// <summary>
        /// Gets the default <see cref="AuthorizationPolicy"/>
        /// </summary>
        /// <returns></returns>
        public async Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        {
            if (_options.Dependencies?.PolicyProvider != null)
            {
                return await _options.Dependencies.PolicyProvider.GetDefaultPolicyAsync();
            }

            return _options.DefaultPolicy;
        }
    }
}

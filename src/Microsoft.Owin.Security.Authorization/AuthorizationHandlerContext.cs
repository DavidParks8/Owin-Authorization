// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Contains authorization information used by <see cref="IAuthorizationHandler"/>.
    /// </summary>
    public class AuthorizationHandlerContext
    {
        private readonly HashSet<IAuthorizationRequirement> _pendingRequirements;
        private bool _succeedCalled;

        public IEnumerable<IAuthorizationRequirement> Requirements { get; }
        public ClaimsPrincipal User { get; }
        public object Resource { get; }

        public IEnumerable<IAuthorizationRequirement> PendingRequirements => _pendingRequirements;

        public bool HasFailed { get; private set; }

        public bool HasSucceeded => !HasFailed && _succeedCalled && !PendingRequirements.Any();

        public AuthorizationHandlerContext(
            IEnumerable<IAuthorizationRequirement> requirements,
            ClaimsPrincipal user,
            object resource)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            Requirements = requirements;
            User = user;
            Resource = resource;
            _pendingRequirements = new HashSet<IAuthorizationRequirement>(requirements);
        }

        public void Fail()
        {
            HasFailed = true;
        }

        public void Succeed(IAuthorizationRequirement requirement)
        {
            _succeedCalled = true;
            _pendingRequirements.Remove(requirement);
        }
    }
}
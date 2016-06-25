// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.Properties;

namespace Microsoft.Owin.Security.Authorization
{
    public class DefaultAuthorizationService : IAuthorizationService
    {
        private readonly IAuthorizationPolicyProvider _policyProvider;
        private readonly IList<IAuthorizationHandler> _handlers;
        private readonly ILogger _logger;

        public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizationHandler> handlers) 
            : this(policyProvider, handlers, null)
        { }

        public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizationHandler> handlers, ILogger logger)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = InitializeHandlers(handlers);
            _policyProvider = policyProvider;
            _logger = logger ?? new DiagnosticsLoggerFactory().Create("ResourceAuthorization");
        }

        private static IList<IAuthorizationHandler> InitializeHandlers(IEnumerable<IAuthorizationHandler> handlers)
        {
            Debug.Assert(handlers != null, "handlers != null");

            var allHandlers = new List<IAuthorizationHandler>();
            bool passThroughFound = false;
            foreach (var handler in handlers)
            {
                if (handler is PassThroughAuthorizationHandler)
                {
                    passThroughFound = true;
                }

                allHandlers.Add(handler);
            }

            if (!passThroughFound)
            {
                allHandlers.Add(new PassThroughAuthorizationHandler());
            }

            return allHandlers;
        }

        public async Task<bool> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            var authContext = new AuthorizationContext(requirements, user, resource);
            foreach (var handler in _handlers)
            {
                await handler.HandleAsync(authContext);
            }

            if (authContext.HasSucceeded)
            {
                _logger.UserAuthorizationSucceeded(GetUserNameForLogging(user));
                return true;
            }

            _logger.UserAuthorizationFailed(GetUserNameForLogging(user));
            return false;
        }

        private static string GetUserNameForLogging(ClaimsPrincipal user)
        {
            var identity = user?.Identity;
            if (identity != null)
            {
                var name = identity.Name;
                if (name != null)
                {
                    return name;
                }
                return GetClaimValue(identity, "sub")
                    ?? GetClaimValue(identity, ClaimTypes.Name)
                    ?? GetClaimValue(identity, ClaimTypes.NameIdentifier);
            }
            return null;
        }

        private static string GetClaimValue(IIdentity identity, string claimsType)
        {
            return (identity as ClaimsIdentity)?.FindFirst(claimsType)?.Value;
        }

        public async Task<bool> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName)
        {
            if (policyName == null)
            {
                throw new ArgumentNullException(nameof(policyName));
            }

            var policy = await _policyProvider.GetPolicyAsync(policyName);
            if (policy == null)
            {
                throw new InvalidOperationException(ResourceHelper.FormatException_AuthorizationPolicyNotFound(policyName));
            }

            return await this.AuthorizeAsync(user, resource, policy);
        }
    }
}
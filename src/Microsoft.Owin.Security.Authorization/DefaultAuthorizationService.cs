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
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationService"/>.
    /// </summary>
    public class DefaultAuthorizationService : IAuthorizationService
    {
        private readonly IAuthorizationPolicyProvider _policyProvider;
        private readonly IList<IAuthorizationHandler> _handlers;
        private readonly ILogger _logger;
        private readonly IAuthorizationEvaluator _evaluator;
        private readonly IAuthorizationHandlerContextFactory _contextFactory;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> used to provide policies.</param>
        /// <param name="handlers">The handlers used to fulfill <see cref="IAuthorizationRequirement"/>s.</param>
        /// <remarks>Uses the <see cref="DiagnosticsLoggerFactory"/> to create a logger.</remarks>
        public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizationHandler> handlers) 
            : this(policyProvider, handlers, null, new DefaultAuthorizationHandlerContextFactory(), new DefaultAuthorizationEvaluator())
        { }

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/> used to provide policies.</param>
        /// <param name="handlers">The handlers used to fulfill <see cref="IAuthorizationRequirement"/>s.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        /// <param name="contextFactory">The <see cref="IAuthorizationHandlerContextFactory"/> used to create the context to handle the authorization.</param>  
        /// <param name="evaluator">The <see cref="IAuthorizationEvaluator"/> used to determine if authorzation was successful.</param>
        public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizationHandler> handlers, ILogger logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }
            if (contextFactory == null)
            {
                throw new ArgumentNullException(nameof(contextFactory));
            }
            if (evaluator == null)
            {
                throw new ArgumentNullException(nameof(evaluator));
            }

            _handlers = InitializeHandlers(handlers);
            _policyProvider = policyProvider;
            _logger = logger ?? new DiagnosticsLoggerFactory().CreateDefaultLogger();
            _contextFactory = contextFactory;
            _evaluator = evaluator;
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

        /// <summary>
        /// Checks if a user meets a specific set of requirements for the specified resource.
        /// </summary>
        /// <param name="user">The user to evaluate the requirements against.</param>
        /// <param name="resource">The resource to evaluate the requirements against.</param>
        /// <param name="requirements">The requirements to evaluate.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeded.
        /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
        /// </returns>
        public async Task<bool> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            var authContext = _contextFactory.CreateContext(requirements, user, resource);
            foreach (var handler in _handlers)
            {
                await handler.HandleAsync(authContext);
            }

            if (_evaluator.HasSucceeded(authContext))
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
            var claimsIdentity = identity as ClaimsIdentity;
            // ReSharper disable once UseNullPropagation because it compiles to more efficient IL
            if (claimsIdentity != null)
            {
                var claim = claimsIdentity.FindFirst(claimsType);
                if (claim != null)
                {
                    return claim.Value;
                }
            }

            return null;
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy.
        /// </summary>
        /// <param name="user">The user to check the policy against.</param>
        /// <param name="resource">The resource the policy should be checked with.</param>
        /// <param name="policyName">The name of the policy to check against a specific context.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeded.
        /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
        /// </returns>
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
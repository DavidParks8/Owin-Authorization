using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization;
using Microsoft.Owin.Security.Authorization.Infrastructure;

namespace WebApi_Custom_Handler
{
    public class CustomAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        private readonly ILoggerFactory _loggerFactory;

        private readonly IAuthorizationHandler[] _handlers;

        public CustomAuthorizationDependenciesFactory(ILoggerFactory loggerFactory, params IAuthorizationHandler[] handlers)
        {
            _loggerFactory = loggerFactory;
            _handlers = handlers;
        }

        public AuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            var handlers = new List<IAuthorizationHandler>();
            if (_handlers != null)
            {
                handlers.AddRange(_handlers);
            }
            handlers.Add(new PassThroughAuthorizationHandler());
            var policyProvider = new CustomAuthorizationPolicyProvider(options);
            return new AuthorizationDependencies
            {
                PolicyProvider = policyProvider,
                Service = new DefaultAuthorizationService(
                    policyProvider,
                    handlers,
                    _loggerFactory?.Create("ResourceAuthorization"))
            };
        }
    }
}
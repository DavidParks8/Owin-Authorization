using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Owin.Logging;
using Owin;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    public static class AppBuilderExtensions
    {
        private static AuthorizationOptions InitializeDependencies(this AuthorizationOptions options)
        {
            Debug.Assert(options != null);

            if (options.Dependencies == null)
            {
                options.Dependencies = new AuthorizeDependencies();
            }

            if (options.Dependencies.Handler == null)
            {
                options.Dependencies.Handler = () => new PassThroughAuthorizationHandler();
            }

            if (options.Dependencies.PolicyProvider == null)
            {
                options.Dependencies.PolicyProvider = () => new DefaultAuthorizationPolicyProvider(options);
            }

            if (options.Dependencies.LoggerFactory == null)
            {
                options.Dependencies.LoggerFactory = new DiagnosticsLoggerFactory();
            }

            if (options.Dependencies.Service == null)
            {
                options.Dependencies.Service = () => new DefaultAuthorizationService(
                options.Dependencies.PolicyProvider(),
                new List<IAuthorizationHandler>() { options.Dependencies.Handler() },
                options.Dependencies.LoggerFactory.Create(options.GetType().Name));
            }

            return options;
        }

        public static IAppBuilder UseAuthorization(this IAppBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return UseAuthorization(app, new AuthorizationOptions());
        }

        public static IAppBuilder UseAuthorization(this IAppBuilder app, AuthorizationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.Use(typeof(ResourceAuthorizationMiddleware), options.InitializeDependencies());
        }

        public static IAppBuilder UseAuthorization(this IAppBuilder app, Action<AuthorizationOptions> configure)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure));
            }

            var options = new AuthorizationOptions();
            configure(options);
            return UseAuthorization(app, options);
        }
    }
}

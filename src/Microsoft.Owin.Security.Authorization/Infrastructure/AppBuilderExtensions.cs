using System;
using System.Diagnostics;
using Microsoft.Owin.Logging;
using Owin;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    public static class AppBuilderExtensions
    {
        private static AuthorizationOptions InitializeDependencies(AuthorizationOptions options)
        {
            Debug.Assert(options != null);

            if (options.Dependencies == null)
            {
                options.Dependencies = new AuthorizationDependencies();
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

            return app.Use(typeof(ResourceAuthorizationMiddleware), InitializeDependencies(options));
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

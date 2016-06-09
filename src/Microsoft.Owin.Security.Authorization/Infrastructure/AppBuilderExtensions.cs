using System;
using Microsoft.Owin.Logging;
using Owin;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    public static class AppBuilderExtensions
    {
        public static IAppBuilder UseAuthorization(this IAppBuilder app, AuthorizationOptions options, AuthorizationDependenciesProvider dependenciesProvider = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            return app.Use(typeof(ResourceAuthorizationMiddleware), options, dependenciesProvider ?? new AuthorizationDependenciesProvider(options.PolicyProvider, options.Handlers, app.GetLoggerFactory()));
        }

        public static IAppBuilder UseAuthorization(this IAppBuilder app, Action<AuthorizationOptions> configure = null, AuthorizationDependenciesProvider dependenciesProvider = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            var options = new AuthorizationOptions();
            configure?.Invoke(options);
            return UseAuthorization(app, options, dependenciesProvider);
        }
    }
}

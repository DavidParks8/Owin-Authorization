using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware : OwinMiddleware
    {
        private readonly AuthorizationDependenciesProvider _dependenciesProvider;
        private readonly AuthorizationOptions _options;

        public ResourceAuthorizationMiddleware(OwinMiddleware next, AuthorizationOptions options,
            AuthorizationDependenciesProvider dependenciesProvider) : base(next)
        {
            _options = options;
            _dependenciesProvider = dependenciesProvider;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var dependencies = _dependenciesProvider.Create(_options);
            try
            {
                context.SetDependencies(dependencies);
                if (Next != null)
                    await Next.Invoke(context);
            }
            finally
            {
                _dependenciesProvider.Dispose(_options, dependencies);
            }
        }
    }
}
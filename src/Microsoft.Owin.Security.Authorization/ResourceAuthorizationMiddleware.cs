using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware : OwinMiddleware
    {
        private readonly AuthorizationOptions _options;

        private readonly IAuthorizationDependenciesProvider _dependenciesProvider;

        public ResourceAuthorizationMiddleware(OwinMiddleware next, AuthorizationOptions options,
            IAuthorizationDependenciesProvider dependenciesProvider) : base(next)
        {
            _options = options;
            _dependenciesProvider = dependenciesProvider;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var dependencies = _dependenciesProvider.OnCreate?.Invoke(_options, context);
            try
            {
                if (dependencies != null)
                {
                    context.SetDependencies(dependencies);
                }
                if (Next != null)
                {
                    await Next.Invoke(context);
                }
            }
            finally
            {
                _dependenciesProvider.OnDispose?.Invoke(_options, context, dependencies);
            }
        }
    }
}
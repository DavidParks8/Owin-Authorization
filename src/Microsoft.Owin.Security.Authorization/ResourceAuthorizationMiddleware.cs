using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware : OwinMiddleware
    {
        private readonly AuthorizationOptions _options;

        private readonly IAuthorizationDependenciesFactory _dependenciesFactory;

        public ResourceAuthorizationMiddleware(OwinMiddleware next, AuthorizationOptions options,
            IAuthorizationDependenciesFactory dependenciesFactory) : base(next)
        {
            _options = options;
            _dependenciesFactory = dependenciesFactory;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var dependencies = _dependenciesFactory.Create(_options, context);
            if (dependencies != null)
            {
                context.SetDependencies(dependencies);
            }
            if (Next != null)
            {
                await Next.Invoke(context);
            }
        }
    }
}
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class ResourceAuthorizationMiddleware : OwinMiddleware
    {
        public const string ServiceKey = "idm:resourceAuthorizationService";

        private readonly AuthorizationOptions _options;

        public ResourceAuthorizationMiddleware(OwinMiddleware next, AuthorizationOptions options) 
            : base(next)
        {
            _options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            context.Set(ServiceKey, _options);
            if (Next != null)
            {
                await Next.Invoke(context);
            }
        }
    }
}
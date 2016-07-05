using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Implements the middleware pattern for authorization.
    /// </summary>
    public class ResourceAuthorizationMiddleware : OwinMiddleware
    {
        internal const string ServiceKey = "idm:resourceAuthorizationService";

        private readonly AuthorizationOptions _options;

        /// <summary>
        /// Creates a new <see cref="ResourceAuthorizationMiddleware"/>.
        /// </summary>
        /// <param name="next">An optional pointer to the next middleware in the pipeline.</param>
        /// <param name="options">Programmatically set <see cref="AuthorizationOptions"/> for use in configuring authorization.</param>
        public ResourceAuthorizationMiddleware(OwinMiddleware next, AuthorizationOptions options) 
            : base(next)
        {
            _options = options;
        }

        /// <summary>
        /// Process an individual request.
        /// </summary>
        /// <param name="context">The <see cref="IOwinContext"/> for the current request.</param>
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
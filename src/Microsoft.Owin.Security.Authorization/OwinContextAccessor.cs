using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    public class OwinContextAccessor : IOwinContextAccessor
    { 
        public IOwinContext GetOwinContext(HttpContextBase httpContext)
        {
            return httpContext.GetOwinContext();
        }
    }
}

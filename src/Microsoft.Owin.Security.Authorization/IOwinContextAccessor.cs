using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IOwinContextAccessor
    {
        IOwinContext GetOwinContext(HttpContextBase httpContext);
    }
}

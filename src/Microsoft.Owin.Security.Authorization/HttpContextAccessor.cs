using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    public class HttpContextAccessor : IHttpContextAccessor
    {
        public HttpContextBase Context => new HttpContextWrapper(HttpContext.Current);
    }
}
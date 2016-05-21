using System.Diagnostics.CodeAnalysis;
using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    public class HttpContextAccessor : IHttpContextAccessor
    {
        [ExcludeFromCodeCoverage] // too little roi to test
        public HttpContextBase Context => new HttpContextWrapper(HttpContext.Current);
    }
}
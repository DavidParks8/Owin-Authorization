using System.Diagnostics.CodeAnalysis;
using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// Allows for easy access of the <see cref="HttpContextBase"/>
    /// </summary>
    public class HttpContextAccessor : IHttpContextAccessor
    {
        [ExcludeFromCodeCoverage] // too little roi to test
        public HttpContextBase Context => new HttpContextWrapper(HttpContext.Current);
    }
}
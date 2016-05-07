using System.Web;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IHttpContextAccessor
    {
        HttpContextBase Context { get; }
    }
}
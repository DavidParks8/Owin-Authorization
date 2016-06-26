using System;
using System.Web;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    /// <summary>
    /// Allows for easy access of the <see cref="IOwinContext"/>
    /// </summary>
    public class HttpContextBaseOwinContextAccessor : IOwinContextAccessor
    {
        private readonly HttpContextBase _httpContextBase;

        public IOwinContext Context => _httpContextBase.GetOwinContext();

        public HttpContextBaseOwinContextAccessor(HttpContextBase httpContextBase)
        {
            if (httpContextBase == null)
            {
                throw new ArgumentNullException(nameof(httpContextBase));
            }

            _httpContextBase = httpContextBase;
        }
    }
}

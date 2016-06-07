using System;
using System.Net.Http;

namespace Microsoft.Owin.Security.Authorization.WebApi
{
    /// <summary>
    /// Allows for easy access of the <see cref="IOwinContext"/>
    /// </summary>
    public class HttpRequestMessageOwinContextAccessor : IOwinContextAccessor
    {
        private readonly HttpRequestMessage _httpRequestMessage;

        public IOwinContext Context => _httpRequestMessage.GetOwinContext();

        public HttpRequestMessageOwinContextAccessor(HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
            {
                throw new ArgumentNullException(nameof(httpRequestMessage));
            }

            _httpRequestMessage = httpRequestMessage;
        }
    }
}

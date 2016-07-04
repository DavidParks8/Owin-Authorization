using System;
using System.Net.Http;

namespace Microsoft.Owin.Security.Authorization.WebApi
{
    /// <summary>
    /// Allows for easy access of the <see cref="IOwinContext"/> in a <see cref="System.Net.Http"/> environment.
    /// </summary>
    public class HttpRequestMessageOwinContextAccessor : IOwinContextAccessor
    {
        private readonly WeakReference<HttpRequestMessage> _httpRequestMessage;

        /// <summary>
        /// Gets an <see cref="IOwinContext"/>.
        /// </summary>
        public IOwinContext Context
        {
            get
            {
                HttpRequestMessage request;
                if (_httpRequestMessage.TryGetTarget(out request))
                {
                    return request.GetOwinContext();
                }
                return null;
            }
        }

        public HttpRequestMessageOwinContextAccessor(HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
            {
                throw new ArgumentNullException(nameof(httpRequestMessage));
            }

            _httpRequestMessage = new WeakReference<HttpRequestMessage>(httpRequestMessage);
        }
    }
}

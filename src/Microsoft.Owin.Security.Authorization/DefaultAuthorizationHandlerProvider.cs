using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
    {
        private readonly IAuthorizationHandler[] _handlers;

        public DefaultAuthorizationHandlerProvider(params IAuthorizationHandler[] handlers)
        {
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = handlers;
        }

        public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync()
        {
            return Task.FromResult((IEnumerable<IAuthorizationHandler>)_handlers);
        }
    }
}
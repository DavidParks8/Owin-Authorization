using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationHandlerProvider"/>.
    /// </summary>
    public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
    {
        private readonly IAuthorizationHandler[] _handlers;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationHandlerProvider"/>.
        /// </summary>
        /// <param name="handlers">An array of <see cref="IAuthorizationHandler"/>s to help decide if a user is authorized.</param>
        public DefaultAuthorizationHandlerProvider(params IAuthorizationHandler[] handlers)
        {
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = handlers;
        }

        /// <summary>
        /// Retrieves an enumeration of <see cref="IAuthorizationHandler"/>s which should be used to evaluate authorization.
        /// </summary>
        /// <returns>An <see cref="IEnumerable{IAuthorizationHandler}"/> for use in deciding if authorization is allowed.</returns>
        public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync()
        {
            return Task.FromResult((IEnumerable<IAuthorizationHandler>)_handlers);
        }
    }
}
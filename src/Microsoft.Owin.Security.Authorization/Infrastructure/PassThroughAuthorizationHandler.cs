// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    public class PassThroughAuthorizationHandler : IAuthorizationHandler
    {
        public async Task HandleAsync(AuthorizationHandlerContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            foreach (var handler in context.Requirements.OfType<IAuthorizationHandler>())
            {
                await handler.HandleAsync(context);
            }
        }
    }
}

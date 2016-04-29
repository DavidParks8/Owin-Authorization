// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Logging;

namespace Microsoft.Owin.Security.Authorization
{
    internal static class LoggingExtensions
    {
        public static void UserAuthorizationSucceeded(this ILogger logger, string userName)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            logger.WriteInformation($"Authorization was successful for user: {userName}");
        }

        public static void UserAuthorizationFailed(this ILogger logger, string userName)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            logger.WriteInformation($"Authorization failed for user: {userName}");
        }
    }
}

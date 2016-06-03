// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.Properties;

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

            logger.WriteInformation(string.Format(CultureInfo.CurrentCulture, Resources.LogAuthorizationSucceededForUser, userName));
        }

        public static void UserAuthorizationFailed(this ILogger logger, string userName)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            logger.WriteInformation(string.Format(CultureInfo.CurrentCulture, Resources.LogAuthorizationFailedForUser, userName));
        }
    }
}

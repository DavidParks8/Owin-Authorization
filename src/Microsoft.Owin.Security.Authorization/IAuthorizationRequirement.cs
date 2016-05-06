// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Owin.Security.Authorization
{
    [SuppressMessage("Microsoft.Design", "CA1040:AvoidEmptyInterfaces", Justification = "Used as a pivot point for common functionality")]
    public interface IAuthorizationRequirement
    {
    }
}

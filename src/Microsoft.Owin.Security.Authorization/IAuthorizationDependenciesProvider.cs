using System;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationDependenciesProvider
    {
        Func<AuthorizationOptions, IOwinContext, AuthorizationDependencies> OnCreate { get; }

        Action<AuthorizationOptions, IOwinContext, AuthorizationDependencies> OnDispose { get; }
    }
}
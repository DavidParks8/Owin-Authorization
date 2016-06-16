using System;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationDependenciesFactory
    {
        AuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext);
    }
}
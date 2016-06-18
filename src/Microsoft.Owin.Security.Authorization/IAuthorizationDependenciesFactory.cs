using System;

namespace Microsoft.Owin.Security.Authorization
{
    public interface IAuthorizationDependenciesFactory
    {
        IAuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext);
    }
}
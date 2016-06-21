using Autofac;
using Autofac.Integration.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Authorization;

namespace WebApi_Autofac
{
    public class AutofacAuthorizationDependenciesFactory : IAuthorizationDependenciesFactory
    {
        public IAuthorizationDependencies Create(AuthorizationOptions options, IOwinContext owinContext)
        {
            return owinContext.GetAutofacLifetimeScope().Resolve<IAuthorizationDependencies>();
        }
    }
}
using System;
using Autofac;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization;
// ReSharper disable ValueParameterNotUsed

namespace WebApi_Autofac
{
    public class AutofacAuthorizationDependencies : AuthorizationDependencies
    {
        private readonly IComponentContext _resolver;

        public AutofacAuthorizationDependencies(IComponentContext resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        public override IAuthorizationService Service
        {
            get { return _resolver.Resolve<IAuthorizationService>(); }
            set { DisallowSetMethod(); }
        }

        public override ILoggerFactory LoggerFactory
        {
            get { return _resolver.Resolve<ILoggerFactory>(); }
            set { DisallowSetMethod(); }
        }

        public override IAuthorizationPolicyProvider PolicyProvider
        {
            get { return _resolver.Resolve<IAuthorizationPolicyProvider>(); }
            set { DisallowSetMethod(); }
        }

        private static void DisallowSetMethod()
        {
            throw new InvalidOperationException("Set is not a valid operation.  Instead, register the component for resolution.");
        }
    }
}
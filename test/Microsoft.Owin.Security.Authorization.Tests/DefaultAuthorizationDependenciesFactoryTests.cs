using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationDependenciesFactoryTests
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationDependenciesFactory", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenHandlersIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationDependenciesFactory(null);
        }

        [TestMethod, UnitTest]
        public void CreateShouldNotReturnNull()
        {
            var dependenciesFactory = new DefaultAuthorizationDependenciesFactory();
            var dependencies = dependenciesFactory.Create(new AuthorizationOptions(), null);
            Assert.IsNotNull(dependencies, "dependencies != null");
        }

        [TestMethod, UnitTest]
        public void CreateShouldReturnWithDependenciesInitialized()
        {
            var dependenciesFactory = new DefaultAuthorizationDependenciesFactory();
            var dependencies = dependenciesFactory.Create(new AuthorizationOptions(), null);
            Assert.IsInstanceOfType(dependencies.LoggerFactory, typeof(DiagnosticsLoggerFactory));
            Assert.IsInstanceOfType(dependencies.PolicyProvider, typeof(DefaultAuthorizationPolicyProvider));
            Assert.IsInstanceOfType(dependencies.Service, typeof(DefaultAuthorizationService));
        }
    }
}

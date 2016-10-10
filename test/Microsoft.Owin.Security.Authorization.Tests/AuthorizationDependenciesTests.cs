using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationDependenciesTests
    {
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateShouldThrowWhenHandlersIsNull()
        {
            AuthorizationDependencies.Create(new AuthorizationOptions(), null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateShouldThrowWhenOptionsIsNull()
        {
            AuthorizationDependencies.Create(null);
        }

        [TestMethod, UnitTest]
        public void CreateShouldNotReturnNull()
        {
            var dependencies = AuthorizationDependencies.Create(new AuthorizationOptions());
            Assert.IsNotNull(dependencies, "dependencies != null");
        }

        [TestMethod, UnitTest]
        public void CreateShouldReturnWithDependenciesInitialized()
        {
            var dependencies = AuthorizationDependencies.Create(new AuthorizationOptions());
            Assert.IsInstanceOfType(dependencies.LoggerFactory, typeof(DiagnosticsLoggerFactory));
            Assert.IsInstanceOfType(dependencies.PolicyProvider, typeof(DefaultAuthorizationPolicyProvider));
            Assert.IsInstanceOfType(dependencies.Service, typeof(DefaultAuthorizationService));
        }
    }
}

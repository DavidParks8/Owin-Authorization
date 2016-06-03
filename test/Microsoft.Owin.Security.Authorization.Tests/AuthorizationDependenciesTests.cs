using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationDependenciesTests
    {
        [TestMethod, UnitTest]
        public void AdditionalHandlersShouldNotBeNull()
        {
            var dependencies = new AuthorizationDependencies();
            Assert.IsNotNull(dependencies.AdditionalHandlers, "dependencies.AdditionalHandlers != null");
        }

        [TestMethod, UnitTest]
        public void AdditionalHandlersShouldHaveNoSetter()
        {
            var property = typeof(AuthorizationDependencies).GetProperty(nameof(AuthorizationDependencies.AdditionalHandlers));
            Assert.IsFalse(property.CanWrite, "property.CanWrite");
        }
    }
}

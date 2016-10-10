using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationServiceFactoryTests
    {
        private static IAuthorizationPolicyProvider DefaultPolicyProvider()
        {
            return new DefaultAuthorizationPolicyProvider(new AuthorizationOptions());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateWithNullPolicyProviderShouldThrow()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            factory.Create(null, new IAuthorizationHandler[0], new DiagnosticsLoggerFactory(), new DefaultAuthorizationHandlerContextFactory(), new DefaultAuthorizationEvaluator());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateWithNullHandlersShouldThrow()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            factory.Create(DefaultPolicyProvider(), null, new DiagnosticsLoggerFactory(), new DefaultAuthorizationHandlerContextFactory(), new DefaultAuthorizationEvaluator());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateWithNullLoggerFactoryShouldThrow()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            factory.Create(DefaultPolicyProvider(), new IAuthorizationHandler[0], null, new DefaultAuthorizationHandlerContextFactory(), new DefaultAuthorizationEvaluator());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateWithNullContextFactoryShouldThrow()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            factory.Create(DefaultPolicyProvider(), new IAuthorizationHandler[0], new DiagnosticsLoggerFactory(), null, new DefaultAuthorizationEvaluator());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CreateWithNullEvaluatorShouldThrow()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            factory.Create(DefaultPolicyProvider(), new IAuthorizationHandler[0], new DiagnosticsLoggerFactory(), new DefaultAuthorizationHandlerContextFactory(), null);
        }

        [TestMethod, UnitTest]
        public void CreateShouldReturnDefaultAuthorizationService()
        {
            var factory = new DefaultAuthorizationServiceFactory();
            var authorizationService = factory.Create(
                DefaultPolicyProvider(),
                new IAuthorizationHandler[0],
                new DiagnosticsLoggerFactory(),
                new DefaultAuthorizationHandlerContextFactory(),
                new DefaultAuthorizationEvaluator());
            Assert.IsInstanceOfType(authorizationService, typeof(DefaultAuthorizationService));
        }
    }
}

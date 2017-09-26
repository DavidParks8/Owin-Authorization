using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class OwinContextExtensionsTests : TestClassBase
    {
        private const string _messageId = "Microsoft.Owin.Security.Authorization." + nameof(OwinContextExtensions);

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ThrowWhenPassedNullContext()
        {
            // ReSharper disable once ObjectCreationAsStatement
            OwinContextExtensions.GetAuthorizationOptions(null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ThrowWhenPassedNullEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            owinContext.Setup(x => x.Environment).Returns<IDictionary<string, object>>(null);
            // ReSharper disable once ObjectCreationAsStatement
            owinContext.Object.GetAuthorizationOptions();
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest]
        public void ThrowWhenOptionsNotFoundInEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object>();
            owinContext.Setup(x => x.Environment).Returns(environment);
            try
            {
                // ReSharper disable once ObjectCreationAsStatement
                owinContext.Object.GetAuthorizationOptions();
                Assert.Fail("No exception was thrown");
            }
            catch (InvalidOperationException exception)
            {
                Assert.AreEqual(Properties.Resources.Exception_PleaseSetupOwinResourceAuthorizationInYourStartupFile, exception.Message);
            }
        }

        [TestMethod, UnitTest]
        public void OptionsPropertyShouldBeSetWhenPresentInTheEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object>();
            var options = new AuthorizationOptions();
            environment.Add(ResourceAuthorizationMiddleware.ServiceKey, options);
            owinContext.Setup(x => x.Environment).Returns(environment);
            var actualOptions = owinContext.Object.GetAuthorizationOptions();
            Assert.AreSame(options, actualOptions);
        }

        [TestMethod, UnitTest]
        public void AuthorizationServiceShouldBeNullWhenDependenciesIsNull()
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object>();
            var options = new AuthorizationOptions()
            {
                Dependencies = null
            };
            environment.Add(ResourceAuthorizationMiddleware.ServiceKey, options);
            owinContext.Setup(x => x.Environment).Returns(environment);
            var authorizationService = owinContext.Object.GetAuthorizationService();
            Assert.IsNull(authorizationService);
        }

        [TestMethod, UnitTest]
        public void AuthorizationServiceShouldBeRetrievedFromOwinContext()
        {
            var service = Repository.Create<IAuthorizationService>();
            var dependencies = Repository.Create<IAuthorizationDependencies>();
            dependencies.Setup(x => x.Service).Returns(service.Object);
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object>();
            var options = new AuthorizationOptions()
            {
                Dependencies = dependencies.Object
            };
            environment.Add(ResourceAuthorizationMiddleware.ServiceKey, options);
            owinContext.Setup(x => x.Environment).Returns(environment);
            var authorizationService = owinContext.Object.GetAuthorizationService();
            Assert.AreSame(service.Object, authorizationService);
        }
    }
}

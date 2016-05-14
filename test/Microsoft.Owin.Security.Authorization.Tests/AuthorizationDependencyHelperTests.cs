using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationDependencyHelperTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationDependencyHelper), Justification = "Expected exception")]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ThrowWhenPassedNullContext()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationDependencyHelper(null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationDependencyHelper), Justification = "Expected exception")]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ThrowWhenPassedNullEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            owinContext.Setup(x => x.Environment).Returns<IDictionary<string, object>>(null);
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationDependencyHelper(owinContext.Object);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationDependencyHelper), Justification = "Expected exception")]
        [TestMethod, UnitTest]
        public void ThrowWhenOptionsNotFoundInEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object>();
            owinContext.Setup(x => x.Environment).Returns(environment);
            try
            {
                // ReSharper disable once ObjectCreationAsStatement
                new AuthorizationDependencyHelper(owinContext.Object);
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
            var helper = new AuthorizationDependencyHelper(owinContext.Object);
            Assert.AreSame(options, helper.AuthorizationOptions);
        }
    }
}


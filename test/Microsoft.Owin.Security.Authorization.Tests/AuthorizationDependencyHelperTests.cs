using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationDependencyHelperTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationDependencyHelper), Justification = "Expected exception")]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AuthorizationDependencyHelperShouldThrowWhenPassedNullContext()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationDependencyHelper(null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationDependencyHelper), Justification = "Expected exception")]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AuthorizationDependencyHelperShouldThrowWhenPassedNullEnvironment()
        {
            var owinContext = Repository.Create<IOwinContext>();
            owinContext.Setup(x => x.Environment).Returns<IDictionary<string, object>>(null);
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationDependencyHelper(owinContext.Object);
        }
    }
}

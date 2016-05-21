using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics.CodeAnalysis;
using System.Web;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class OwinContextAccessorTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization." + nameof(OwinContextAccessor),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenPassedNullHttpContextAccessor()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new OwinContextAccessor(null);
        }

        [TestMethod, UnitTest]
        public void OwinContextShouldBeCreatedFromHttpContext()
        {
            var httpContext = Repository.Create<HttpContextBase>();
            var items = new Hashtable {{"owin.Environment", new Dictionary<string, object>()}};
            httpContext.Setup(x => x.Items).Returns(items);
            var httpContextAccessor = Repository.Create<IHttpContextAccessor>();
            httpContextAccessor.Setup(x => x.Context).Returns(httpContext.Object);
            var owinAccessor = new OwinContextAccessor(httpContextAccessor.Object);
            Assert.IsNotNull(owinAccessor.Context);
            httpContext.Verify(x => x.Items, Times.Once);
        }
    }
}

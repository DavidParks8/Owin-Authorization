using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Web;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    [TestClass, ExcludeFromCodeCoverage]
    public class HttpContextBaseOwinContextAccessorTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.Mvc.HttpContextBaseOwinContextAccessor", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenHttpContextBaseIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new HttpContextBaseOwinContextAccessor(null);
        }

        [TestMethod, UnitTest]
        public void OwinContextShouldBeCreatedFromHttpContextBase()
        {
            var httpContext = Repository.Create<HttpContextBase>();
            var items = new Hashtable { { "owin.Environment", new Dictionary<string, object>() } };
            httpContext.Setup(x => x.Items).Returns(items);
            
            var owinAccessor = new HttpContextBaseOwinContextAccessor(httpContext.Object);
            Assert.IsNotNull(owinAccessor.Context);
            httpContext.Verify(x => x.Items, Times.Once);
        }
    }
}

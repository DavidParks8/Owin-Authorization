using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.WebApi
{
    [TestClass, ExcludeFromCodeCoverage]
    public class HttpRequestMessageOwinContextAccessorTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.WebApi.HttpRequestMessageOwinContextAccessor", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenHttpContextBaseIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new HttpRequestMessageOwinContextAccessor(null);
        }

        [TestMethod, UnitTest]
        public void OwinContextShouldBeCreatedFromHttpRequestMessage()
        {
            using (var request = new HttpRequestMessage())
            {
                request.Properties.Add("MS_OwinEnvironment", new Dictionary<string, object>());
                var owinAccessor = new HttpRequestMessageOwinContextAccessor(request);
                Assert.IsNotNull(owinAccessor.Context);
            }
        }

        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.GC.Collect", Justification = Justifications.ForceObjectToFinalize)]
        [TestMethod, UnitTest]
        public void ContextShouldBeNullAfterFinalize()
        {
            var owinAccessor = CreateWithDisposedRequest();
            GC.Collect();
            Assert.IsNull(owinAccessor.Context);
        }

        private static HttpRequestMessageOwinContextAccessor CreateWithDisposedRequest()
        {
            using (var request = new HttpRequestMessage())
            {
                return new HttpRequestMessageOwinContextAccessor(request);
            }
        }
    }
}

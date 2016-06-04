using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ResourceAuthorizationMiddlewareTests
    {
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.AsyncTestMustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task NextShouldBeInvokedWithOptionsInEnvironment()
        {
            var options = new AuthorizationOptions();
            bool executed = false;
            Func<IDictionary<string, object>, Task> next = environment =>
            {
                executed = true;
                var acquiredOptions = environment[ResourceAuthorizationMiddleware.ServiceKey];
                Assert.AreSame(options, acquiredOptions);
                return Task.FromResult(0);
            };
            var middleware = new ResourceAuthorizationMiddleware(next, options);
            await middleware.Invoke(new Dictionary<string, object>());
            Assert.IsTrue(executed, "executed");
        }
    }
}

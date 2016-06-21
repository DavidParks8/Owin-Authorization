using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ResourceAuthorizationMiddlewareTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task OptionsShouldBeSetInEnvironment()
        {
            var options = new AuthorizationOptions();
            var middleware = new ResourceAuthorizationMiddleware(null, options);
            var mockContext = Repository.Create<IOwinContext>();
            mockContext.Setup(x => x.Set(It.IsAny<string>(), It.IsAny<AuthorizationOptions>())).Returns((IOwinContext)null);

            await middleware.Invoke(mockContext.Object);

            mockContext.Verify(x => x.Set(ResourceAuthorizationMiddleware.ServiceKey, options), Times.Once);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task NextShouldBeInvoked()
        {
            var next = Repository.Create<OwinMiddleware>(null);
            next.Setup(x => x.Invoke(It.IsAny<IOwinContext>())).Returns(Task.FromResult(0));
            var middleware = new ResourceAuthorizationMiddleware(next.Object, new AuthorizationOptions());

            var mockContext = Repository.Create<IOwinContext>();
            mockContext.Setup(x => x.Set(It.IsAny<string>(), It.IsAny<AuthorizationOptions>())).Returns((IOwinContext)null);

            await middleware.Invoke(mockContext.Object);

            next.Verify(x => x.Invoke(mockContext.Object), Times.Once);
        }
    }
}

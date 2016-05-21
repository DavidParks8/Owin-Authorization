using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public class PassThroughAuthorizationHandlerTests : TestClassBase
    {
        [TestMethod, UnitTest]
        public void InfinitePassThroughShouldNotOccur()
        {
            var handler = new PassThroughAuthorizationHandler();
            Assert.IsNotInstanceOfType(handler, typeof(IAuthorizationRequirement));
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.AsyncTestMustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task HandleAsyncShouldThrowWhenContextIsNull()
        {
            var handler = new PassThroughAuthorizationHandler();
            await handler.HandleAsync(null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.AsyncTestMustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldPassThrough()
        {
            var mockRequirementHandler = Repository.Create<IAuthorizationHandler>();
            var innerWasHandled = false;
            mockRequirementHandler.Setup(x => x.HandleAsync(It.IsAny<AuthorizationContext>())).Returns(() =>
            {
                innerWasHandled = true;
                return Task.FromResult(0);
            });

            var context = new AuthorizationContext(new [] { mockRequirementHandler.As<IAuthorizationRequirement>().Object}, null, null);
            var handler = new PassThroughAuthorizationHandler();
            await handler.HandleAsync(context);

            Assert.IsTrue(innerWasHandled, "The inner handler was not called");
        }
    }
}

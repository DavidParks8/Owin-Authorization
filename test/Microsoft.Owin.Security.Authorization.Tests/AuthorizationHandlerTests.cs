using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationHandlerTests
    {
        private class TestRequirement : IAuthorizationRequirement { }

        private class TestHandler : AuthorizationHandler<TestRequirement>
        {
            protected override void Handle(AuthorizationHandlerContext context, TestRequirement requirement)
            {
                context.Succeed(requirement);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleShouldThrowWhenContextIsNull()
        {
            var handler = new TestHandler();
            handler.Handle(null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task HandleAsyncShouldThrowWhenContextIsNull()
        {
            var handler = new TestHandler();
            await handler.HandleAsync(null);
        }

        private static AuthorizationHandlerContext CreateContext(params IAuthorizationRequirement[] requirements)
        {
            return new AuthorizationHandlerContext(requirements, new ClaimsPrincipal(), null);
        }

        [TestMethod, UnitTest]
        public void HandleShouldSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContext(new TestRequirement());
            handler.Handle(context);
            Assert.IsTrue(context.HasSucceeded);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContext(new TestRequirement());
            await handler.HandleAsync(context);
            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod, UnitTest]
        public void HandleShouldNotSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContext(new AssertionRequirement(x => true));
            handler.Handle(context);
            Assert.IsFalse(context.HasSucceeded);
            Assert.IsFalse(context.HasFailed);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldNotSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContext(new AssertionRequirement(x => true));
            await handler.HandleAsync(context);
            Assert.IsFalse(context.HasSucceeded);
            Assert.IsFalse(context.HasFailed);
        }
    }

    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationHandlerResourceTests
    {
        private class TestRequirement : IAuthorizationRequirement { }
        private class TestResource { }

        private class TestHandler : AuthorizationHandler<TestRequirement, TestResource>
        {
            protected override void Handle(AuthorizationHandlerContext context, TestRequirement requirement, TestResource resource)
            {
                context.Succeed(requirement);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleShouldThrowWhenContextIsNull()
        {
            var handler = new TestHandler();
            handler.Handle(null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task HandleAsyncShouldThrowWhenContextIsNull()
        {
            var handler = new TestHandler();
            await handler.HandleAsync(null);
        }

        [TestMethod, UnitTest]
        public void HandleShouldSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContextWhichShouldSucceed();
            handler.Handle(context);
            Assert.IsTrue(context.HasSucceeded);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldSucceed()
        {
            var handler = new TestHandler();
            var context = CreateContextWhichShouldSucceed();
            await handler.HandleAsync(context);
            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod, UnitTest]
        public void HandleShouldNotSucceedWhenRequirementIsMissing()
        {
            RunTestWhichShouldNotSucceed(CreateContextWithDifferentRequirement());
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldNotSucceedWhenRequirementIsMissing()
        {
            await RunTestWhichShouldNotSucceedAsync(CreateContextWithDifferentRequirement());
        }

        [TestMethod, UnitTest]
        public void HandleShouldNotSucceedWhenResourceIsNull()
        {
            RunTestWhichShouldNotSucceed(CreateContextWithNullResource());
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldNotSucceedWhenResourceIsNull()
        {
            await RunTestWhichShouldNotSucceedAsync(CreateContextWithNullResource());
        }

        [TestMethod, UnitTest]
        public void HandleShouldNotSucceedWhenResourceIsTheWrongType()
        {
            RunTestWhichShouldNotSucceed(CreateContextWithTheWrongResourceType());
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldNotSucceedWhenResourceIsTheWrongType()
        {
            await RunTestWhichShouldNotSucceedAsync(CreateContextWithTheWrongResourceType());
        }

        private static AuthorizationHandlerContext CreateContext(object resource, params IAuthorizationRequirement[] requirements)
        {
            return new AuthorizationHandlerContext(requirements, new ClaimsPrincipal(), resource);
        }

        private static AuthorizationHandlerContext CreateContextWhichShouldSucceed()
        {
            return CreateContext(new TestResource(), new TestRequirement());
        }

        private static AuthorizationHandlerContext CreateContextWithDifferentRequirement()
        {
            return CreateContext(new TestResource(), new AssertionRequirement(x => true));
        }

        private static AuthorizationHandlerContext CreateContextWithNullResource()
        {
            return CreateContext(null, new TestRequirement());
        }

        private static AuthorizationHandlerContext CreateContextWithTheWrongResourceType()
        {
            return CreateContext("wrong type", new TestRequirement());
        }

        private static void RunTestWhichShouldNotSucceed(AuthorizationHandlerContext context)
        {
            var handler = new TestHandler();
            handler.Handle(context);
            AssertNoSuccessOrFailure(context);
        }

        private static async Task RunTestWhichShouldNotSucceedAsync(AuthorizationHandlerContext context)
        {
            var handler = new TestHandler();
            await handler.HandleAsync(context);
            AssertNoSuccessOrFailure(context);
        }

        private static void AssertNoSuccessOrFailure(AuthorizationHandlerContext context)
        {
            Assert.IsFalse(context.HasSucceeded);
            Assert.IsFalse(context.HasFailed);
        }
    }
}
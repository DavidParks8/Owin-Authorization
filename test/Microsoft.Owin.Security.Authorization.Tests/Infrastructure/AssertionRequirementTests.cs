using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AssertionRequirementTests : RequirementHandlerTestsBase<AssertionRequirement>
    {
        private const string _messageId = "Microsoft.Owin.Security.Authorization.Infrastructure." + nameof(AssertionRequirement);

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenPassedNullSynchronousFunc()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AssertionRequirement((Func<AuthorizationContext, bool>) null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenPassedNullAsynchronousFunc()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AssertionRequirement((Func<AuthorizationContext, Task<bool>>)null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandlerShouldBeSetWhenPassedSynchronousFunc()
        {
            var funcWasCalled = false;
            var func = new Func<AuthorizationContext, bool>(context =>
            {
                funcWasCalled = true;
                return true;
            });

            var requirement = new AssertionRequirement(func);

            Assert.IsNotNull(requirement.Handler);
            Assert.IsTrue(await requirement.Handler(null), "await requirement.Handler(null)");
            Assert.IsTrue(funcWasCalled, "funcWasCalled");
        }

        [TestMethod, UnitTest]
        public void HandlerShouldBeSetWhenPassedAsynchronousFunc()
        {
            var func = new Func<AuthorizationContext, Task<bool>>(context => Task.FromResult(true));
            var requirement = new AssertionRequirement(func);

            Assert.IsNotNull(requirement.Handler);
            Assert.AreSame(func, requirement.Handler);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public override async Task HandleAsyncShouldThrowWhenPassedNullContext()
        {
            var requirement = new AssertionRequirement(context => true);
            await requirement.HandleAsync(null);
        }

        [TestMethod, UnitTest]
        public override async Task HandleAsyncShouldSucceed()
        {
            var requirement = new AssertionRequirement(x => true);
            await HandleAsyncShouldSucceed(requirement);
        }

        [TestMethod, UnitTest]
        public override async Task HandleAsyncShouldFail()
        {
            var requirement = new AssertionRequirement(x => false);
            await HandleAsyncShouldFail(requirement);
        }
    }
}

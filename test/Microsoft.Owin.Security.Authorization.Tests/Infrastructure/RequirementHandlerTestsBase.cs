using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public abstract class RequirementHandlerTestsBase<TRequirement> : TestClassBase
        where TRequirement : IAuthorizationHandler, IAuthorizationRequirement
    {
        protected async Task HandleAsyncShouldSucceed(TRequirement requirement)
        {
            var context = CreateDefaultAuthorizationContext(requirement);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
            await requirement.HandleAsync(context);
            Assert.IsTrue(context.HasSucceeded, "context.HasSucceeded");
        }

        protected async Task HandleAsyncShouldFail(TRequirement requirement)
        {
            var context = CreateDefaultAuthorizationContext(requirement);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
            await requirement.HandleAsync(context);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
        }

        private static AuthorizationHandlerContext CreateDefaultAuthorizationContext(TRequirement requirement)
        {
            Assert.IsNotNull(requirement);
            return new AuthorizationHandlerContext(new IAuthorizationRequirement[] { requirement }, new ClaimsPrincipal(), null);
        }

        public abstract Task HandleAsyncShouldThrowWhenPassedNullContext();
        public abstract Task HandleAsyncShouldSucceed();
        public abstract Task HandleAsyncShouldFail();
    }
}

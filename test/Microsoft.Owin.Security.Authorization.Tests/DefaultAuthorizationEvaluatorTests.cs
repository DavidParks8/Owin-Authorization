using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationEvaluatorTests : TestClassBase
    {
        [TestMethod, UnitTest]
        public void ContextShouldEvaluateToFailure()
        {
            var context = new AuthorizationHandlerContext(new IAuthorizationRequirement[0], new ClaimsPrincipal(), null);
            Assert.IsFalse(context.HasFailed, "context.HasFailed");
            context.Fail();
            var evaluator = new DefaultAuthorizationEvaluator();
            Assert.IsTrue(evaluator.HasFailed(context), "evaluator.HasFailed(context)");
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HasFailedShouldThrowWhenContextIsNull()
        {
            new DefaultAuthorizationEvaluator().HasFailed(null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HasSucceededShouldThrowWhenContextIsNull()
        {
            new DefaultAuthorizationEvaluator().HasSucceeded(null);
        }

    }
}

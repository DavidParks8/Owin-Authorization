using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationContextTests
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationContext),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenRequirementsIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationContext(null, new ClaimsPrincipal(), new object());
        }

        [TestMethod, UnitTest]
        public void FailShouldSetHasFailed()
        {
            var context = new AuthorizationContext(new IAuthorizationRequirement[0], null, null);
            Assert.IsFalse(context.HasFailed, "context.HasFailed");
            context.Fail();
            Assert.IsTrue(context.HasFailed, "context.HasFailed");
        }

        [TestMethod, UnitTest]
        public void SucceedShouldNotThrowWhenRequirementIsNull()
        {
            var context = new AuthorizationContext(new IAuthorizationRequirement[0], null, null);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
            context.Succeed(null);
            Assert.IsTrue(context.HasSucceeded, "context.HasSucceeded");
        }

        [TestMethod, UnitTest]
        public void FailingShouldPreventSuccess()
        {
            var context = new AuthorizationContext(new IAuthorizationRequirement[0], null, null);
            context.Fail();
            context.Succeed(null);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
        }

        [TestMethod, UnitTest]
        public void SucceedShouldUpdatePendingRequirements()
        {
            var requirements = new IAuthorizationRequirement[]
            {
                new DenyAnonymousAuthorizationRequirement()
            };

            var context = new AuthorizationContext(requirements, null, null);
            Assert.AreEqual(requirements.Length, context.PendingRequirements.Count());
            context.Succeed(requirements[0]);
            Assert.IsFalse(context.PendingRequirements.Any(), "context.PendingRequirements.Any()");
        }

        [TestMethod, UnitTest]
        public void HasSucceededShouldRequireNoPendingRequirements()
        {
            var requirements = new IAuthorizationRequirement[]
            {
                new DenyAnonymousAuthorizationRequirement(),
                new DenyAnonymousAuthorizationRequirement()
            };

            var context = new AuthorizationContext(requirements, null, null);
            context.Succeed(requirements[0]);
            Assert.IsFalse(context.HasSucceeded, "context.HasSucceeded");
            context.Succeed(requirements[1]);
            Assert.IsTrue(context.HasSucceeded, "context.HasSucceeded");
        }

        [TestMethod, UnitTest]
        public void PropertiesShouldBeSet()
        {
            var requirements = new IAuthorizationRequirement[0];
            var user = new ClaimsPrincipal();
            
            var context = new AuthorizationContext(requirements, user, requirements);

            Assert.AreSame(requirements, context.Requirements);
            Assert.AreSame(user, context.User);
            Assert.AreSame(requirements, context.Resource);
        }
    }
}

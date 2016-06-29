using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ClaimsAuthorizationRequirementTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task NullAllowedValuesShouldSucceed()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", null);
            await AssertMissingAllowedValuesShouldSucceed(requirement);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task EmptyAllowedValuesShouldSucceed()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", new List<string>());
            await AssertMissingAllowedValuesShouldSucceed(requirement);
        }

        private static ClaimsPrincipal UserWithClaim(string claimType)
        {
            var identity = new ClaimsIdentity(new[] { new Claim(claimType, "") });
            return new ClaimsPrincipal(identity);
        }
        private static async Task AssertMissingAllowedValuesShouldSucceed(ClaimsAuthorizationRequirement requirement)
        {
            Assert.IsNotNull(requirement);

            var context = new AuthorizationHandlerContext(new [] { requirement }, UserWithClaim(requirement.ClaimType), null);
            await requirement.HandleAsync(context);
            Assert.IsTrue(context.HasSucceeded, "context.HasSucceeded");
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", 
            MessageId = "Microsoft.Owin.Security.Authorization.Infrastructure." + nameof(ClaimsAuthorizationRequirement), 
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenClaimTypeIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new ClaimsAuthorizationRequirement(null, new List<string>());
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task HandleAsyncShouldThrowWhenPassedNullContext()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", new string[0]);
            await requirement.HandleAsync(null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenUserIsNull()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", null);
            var context = new AuthorizationHandlerContext(new [] { requirement }, null, null);
            await requirement.HandleAsync(context);
            Assert.IsFalse(context.HasSucceeded);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task DifferentAllowedValuesShouldSucceed()
        {
            var values = new List<string>() { "hi", "test" };
            var requirement = new ClaimsAuthorizationRequirement("asdf", values);
            foreach (var value in values)
            {
                await AssertClaimValueAffectsSuccess(value, requirement, true);
            }

            await AssertClaimValueAffectsSuccess("fdsa", requirement, false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task AllowedValuesShouldBeCaseSensitive()
        {
            const string test = "test";
            var requirement = new ClaimsAuthorizationRequirement("asdf", new []{ test });
            await AssertClaimValueAffectsSuccess(test, requirement, true);
            await AssertClaimValueAffectsSuccess(test.ToUpper(), requirement, false);
        }

        private static async Task AssertClaimValueAffectsSuccess(string claimValue, ClaimsAuthorizationRequirement requirement, bool shouldSucceed)
        {
            var identity = new ClaimsIdentity(new[] { new Claim(requirement.ClaimType, claimValue) });
            var user = new ClaimsPrincipal(identity);

            var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
            await requirement.HandleAsync(context);
            Assert.AreEqual(shouldSucceed, context.HasSucceeded);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task ShouldFailWithoutExpectedClaim()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", new [] { "hi"});
            var context = new AuthorizationHandlerContext(new[] { requirement }, new ClaimsPrincipal(), null);
            await requirement.HandleAsync(context);
            Assert.IsFalse(context.HasSucceeded);
        }

        private class TestClaimsRequirement : ClaimsAuthorizationRequirement
        {
            public TestClaimsRequirement() : base("test", null)
            {
            }

            public void HandleProtected(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
            {
                Handle(context, requirement);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenContextIsNull()
        {
            var requirement = new TestClaimsRequirement();
            requirement.HandleProtected(null, new TestClaimsRequirement());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenRequirementIsNull()
        {
            var requirement = new TestClaimsRequirement();
            var context = new AuthorizationHandlerContext(new IAuthorizationRequirement[0], null, null);
            requirement.HandleProtected(context, null);
        }
    }
}

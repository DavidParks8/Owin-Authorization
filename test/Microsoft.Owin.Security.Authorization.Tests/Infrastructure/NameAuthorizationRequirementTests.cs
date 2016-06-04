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
    public class NameAuthorizationRequirementTests : TestClassBase
    {
        private class TestNameRequirement : NameAuthorizationRequirement
        {
            public TestNameRequirement() : base("asdf")
            {
            }

            public void HandleProtected(AuthorizationContext context, NameAuthorizationRequirement requirement)
            {
                Handle(context, requirement);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenContextIsNull()
        {
            var requirement = new TestNameRequirement();
            requirement.HandleProtected(null, new NameAuthorizationRequirement("fdsa"));
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenRequirementIsNull()
        {
            var requirement = new TestNameRequirement();
            var context = new AuthorizationContext(new List<IAuthorizationRequirement>(), null, null);
            requirement.HandleProtected(context, null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization.Infrastructure." + nameof(NameAuthorizationRequirement),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenNameIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new NameAuthorizationRequirement(null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleShouldFailWhenUserIsNull()
        {
            await AssertNameAffectsSuccess(null, "asdf", false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleShouldFailWhenIdentitiesHaveNoClaims()
        {
            var user = new ClaimsPrincipal(new ClaimsIdentity());
            await AssertNameAffectsSuccess(user, "asdf", false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleShouldSucceedWhenNameClaimIsPresent()
        {
            const string requiredName = "David";
            var successfulIdentity = new ClaimsIdentity();
            successfulIdentity.AddClaim(new Claim(successfulIdentity.NameClaimType, requiredName));
            var identities = new []
            {
                new ClaimsIdentity(),
                successfulIdentity
            };
            var user = new ClaimsPrincipal(identities);
            await AssertNameAffectsSuccess(user, requiredName, true);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task NameComparisonShouldBeCaseInsensitive()
        {
            const string requiredName = "David";
            var successfulIdentity = new ClaimsIdentity();
            successfulIdentity.AddClaim(new Claim(successfulIdentity.NameClaimType, requiredName));
            var user = new ClaimsPrincipal(successfulIdentity);
            await AssertNameAffectsSuccess(user, requiredName.ToUpper(), true);
        }

        private static async Task AssertNameAffectsSuccess(ClaimsPrincipal user, string requiredName, bool shouldSucceed)
        {
            var requirement = new NameAuthorizationRequirement(requiredName);
            var context = new AuthorizationContext(new[] { requirement }, user, null);
            await requirement.HandleAsync(context);
            Assert.AreEqual(shouldSucceed, context.HasSucceeded);
        }
    }
}

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
    public class DenyAnonymousAuthorizationRequirementTests
    {
        private class TestDenyAnonymousRequirement : DenyAnonymousAuthorizationRequirement
        {
            public async Task HandleProtectedAsync(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
            {
                await HandleRequirementAsync(context, requirement);
            }    
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task HandleProtectedShouldThrowWhenContextIsNull()
        {
            var requirement = new TestDenyAnonymousRequirement();
            await requirement.HandleProtectedAsync(null, new TestDenyAnonymousRequirement());
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenUserIsNull()
        {
            await AssertUserAnonymousAffectsSuccess(null, false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenIdentityIsNull()
        {
            await AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(), false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenIdentityIsAnonymous()
        {
            var identity = new ClaimsIdentity();
            await AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(identity), false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldSucceedWhenAnIdentityIsAuthenticated()
        {
            var identities = new List<ClaimsIdentity>()
            {
                new ClaimsIdentity(),
                new ClaimsIdentity(new Claim[0], "This string makes it authenticated")
            };

            await AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(identities), true);
        }

        private static async Task AssertUserAnonymousAffectsSuccess(ClaimsPrincipal user, bool shouldSucceed)
        {
            var requirement = new DenyAnonymousAuthorizationRequirement();
            var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
            await requirement.HandleAsync(context);
            Assert.AreEqual(shouldSucceed, context.HasSucceeded);
        }
    }
}

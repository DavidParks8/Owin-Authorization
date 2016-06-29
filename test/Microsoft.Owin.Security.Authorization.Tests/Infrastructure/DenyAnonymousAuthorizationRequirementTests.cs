using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DenyAnonymousAuthorizationRequirementTests
    {
        private class TestDenyAnonymousRequirement : DenyAnonymousAuthorizationRequirement
        {
            public void HandleProtected(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
            {
                Handle(context, requirement);
            }    
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenContextIsNull()
        {
            var requirement = new TestDenyAnonymousRequirement();
            requirement.HandleProtected(null, new TestDenyAnonymousRequirement());
        }

        [TestMethod, UnitTest]
        public void HandleShouldFailWhenUserIsNull()
        {
            AssertUserAnonymousAffectsSuccess(null, false);
        }

        [TestMethod, UnitTest]
        public void HandleShouldFailWhenIdentityIsNull()
        {
            AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(), false);
        }

        [TestMethod, UnitTest]
        public void HandleShouldFailWhenIdentityIsAnonymous()
        {
            var identity = new ClaimsIdentity();
            AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(identity), false);
        }

        [TestMethod, UnitTest]
        public void HandleShouldSucceedWhenAnIdentityIsAuthenticated()
        {
            var identities = new List<ClaimsIdentity>()
            {
                new ClaimsIdentity(),
                new ClaimsIdentity(new Claim[0], "This string makes it authenticated")
            };

            AssertUserAnonymousAffectsSuccess(new ClaimsPrincipal(identities), true);
        }

        private static void AssertUserAnonymousAffectsSuccess(ClaimsPrincipal user, bool shouldSucceed)
        {
            var requirement = new DenyAnonymousAuthorizationRequirement();
            var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);
            requirement.Handle(context);
            Assert.AreEqual(shouldSucceed, context.HasSucceeded);
        }
    }
}

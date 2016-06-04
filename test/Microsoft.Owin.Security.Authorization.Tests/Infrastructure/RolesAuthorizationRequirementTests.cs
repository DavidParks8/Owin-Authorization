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
    public class RolesAuthorizationRequirementTests : TestClassBase
    {
        private class TestRolesRequirement : RolesAuthorizationRequirement
        {
            public TestRolesRequirement() : base(new []{"asdf"}) { }

            public void HandleProtected(AuthorizationContext context, RolesAuthorizationRequirement requirement)
            {
                Handle(context, requirement);
            }
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization.Infrastructure." + nameof(RolesAuthorizationRequirement),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenAllowedRolesIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new RolesAuthorizationRequirement(null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization.Infrastructure." + nameof(RolesAuthorizationRequirement),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest]
        public void ConstructorShouldThrowWhenAllowedRolesIsEmpty()
        {
            try
            {
                // ReSharper disable once ObjectCreationAsStatement
                new RolesAuthorizationRequirement(new List<string>());
                FailWhenNoExceptionIsThrown();
            }
            catch (InvalidOperationException exception)
            {
                Assert.AreEqual(Properties.Resources.Exception_RoleRequirementEmpty, exception.Message);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenContextIsNull()
        {
            var requirement = new TestRolesRequirement();
            requirement.HandleProtected(null, new TestRolesRequirement());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void HandleProtectedShouldThrowWhenRequirementIsNull()
        {
            var requirement = new TestRolesRequirement();
            var context = new AuthorizationContext(new [] { requirement }, null, null);
            requirement.HandleProtected(context, null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenUserIsNull()
        {
            await AssertRolesAffectSuccess(null, new[] {"asdf"}, false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldFailWhenNoRoleClaimIsPresent()
        {
            await AssertRolesAffectSuccess(new ClaimsPrincipal(), new[] {"asdf"}, false);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task HandleAsyncShouldSucceedWhenRoleClaimIsPresent()
        {
            const string role = "Ninja";
            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(identity.RoleClaimType, role));
            await AssertRolesAffectSuccess(new ClaimsPrincipal(identity), new[] { role }, true);
        }

        private static async Task AssertRolesAffectSuccess(ClaimsPrincipal user, IEnumerable<string> allowedRoles, bool shouldSucceed)
        {
            var requirement = new RolesAuthorizationRequirement(allowedRoles);
            var context = new AuthorizationContext(new []{ requirement }, user, null);
            await requirement.HandleAsync(context);
            Assert.AreEqual(shouldSucceed, context.HasSucceeded);
        }
    }
}

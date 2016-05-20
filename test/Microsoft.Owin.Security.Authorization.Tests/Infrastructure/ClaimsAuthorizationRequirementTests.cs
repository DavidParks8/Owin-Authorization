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
    public class ClaimsAuthorizationRequirementTests : RequirementHandlerTestsBase<ClaimsAuthorizationRequirement>
    {
        [TestMethod, UnitTest]
        public async Task NullAllowedValuesShouldSucceed()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", null);
            await AssertMissingAllowedValuesShouldSucceed(requirement);
        }

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

            var context = new AuthorizationContext(new IAuthorizationRequirement[0], UserWithClaim(requirement.ClaimType), null);
            await requirement.HandleAsync(context);
            Assert.IsTrue(context.HasSucceeded, "context.HasSucceeded");
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public override async Task HandleAsyncShouldThrowWhenPassedNullContext()
        {
            var requirement = new ClaimsAuthorizationRequirement("asdf", new string[0]);
            await requirement.HandleAsync(null);
        }

        [TestMethod, UnitTest]
        public override Task HandleAsyncShouldSucceed()
        {
            throw new NotImplementedException();
        }

        [TestMethod, UnitTest]
        public override Task HandleAsyncShouldFail()
        {
            throw new NotImplementedException();
        }
    }
}

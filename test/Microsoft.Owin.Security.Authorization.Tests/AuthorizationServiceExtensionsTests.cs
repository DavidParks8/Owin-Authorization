using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationServiceExtensionsTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncSingleRequirementShouldThrowWhenServiceIsNull()
        {
            await NullService().AuthorizeAsync(AnonymousUser(), Resource(), SingleRequirement());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncSingleRequirementShouldThrowWhenRequirementIsNull()
        {
            var service = MockService().Object;
            await service.AuthorizeAsync(AnonymousUser(), Resource(), (IAuthorizationRequirement)null);
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncSingleRequirementShouldAuthorize()
        {
            await AssertRequirementsAuthorized(service => service.AuthorizeAsync(AnonymousUser(), Resource(), SingleRequirement()));
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyResourceShouldThrowWhenServiceIsNull()
        {
            await NullService().AuthorizeAsync(AnonymousUser(), Resource(), Policy());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyResourceShouldThrowWhenPolicyIsNull()
        {
            await MockService().Object.AuthorizeAsync(AnonymousUser(), Resource(), (AuthorizationPolicy)null);
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncPolicyResourceShouldAuthorize()
        {
            await AssertRequirementsAuthorized(service => service.AuthorizeAsync(AnonymousUser(), Resource(), Policy()));
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyShouldThrowWhenServiceIsNull()
        {
            await NullService().AuthorizeAsync(AnonymousUser(), Policy());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyShouldThrowWhenPolicyIsNull()
        {
            await MockService().Object.AuthorizeAsync(AnonymousUser(), (AuthorizationPolicy)null);
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncPolicyShouldAuthorize()
        {
            await AssertRequirementsAuthorized(service => service.AuthorizeAsync(AnonymousUser(), Policy()));
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyNameShouldThrowWhenServiceIsNull()
        {
            await NullService().AuthorizeAsync(AnonymousUser(), "policy name");
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncPolicyNameShouldThrowWhenPolicyNameIsNull()
        {
            await MockService().Object.AuthorizeAsync(AnonymousUser(), (string)null);
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncPolicyNameShouldAuthorize()
        {
            await AssertPolicyNameAuthorized(service => service.AuthorizeAsync(AnonymousUser(), "policy name"));
        }

        private async Task AssertPolicyNameAuthorized(Func<IAuthorizationService, Task<bool>> authorize)
        {
            await AssertAuthorized(x => x.AuthorizeAsync(
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<object>(),
                It.IsAny<string>()), authorize);
        }

        private async Task AssertRequirementsAuthorized(Func<IAuthorizationService, Task<bool>> authorize)
        {
            await AssertAuthorized(x => x.AuthorizeAsync(
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<object>(),
                It.IsAny<IEnumerable<IAuthorizationRequirement>>()), authorize);
        }

        private async Task AssertAuthorized(
            Expression<Func<IAuthorizationService, Task<bool>>> setup,
            Func<IAuthorizationService, Task<bool>> authorize)
        {
            Assert.IsNotNull(setup, "Your test is invalid");
            Assert.IsNotNull(authorize, "Your test is invalid");

            var service = MockService();
            service.Setup(setup).Returns(Task.FromResult(true));
            var authorized = await authorize(service.Object);
            Assert.IsTrue(authorized, "authorized");
            service.Verify(setup, Times.Once);
        }

        private Mock<IAuthorizationService> MockService()
        {
            return Repository.Create<IAuthorizationService>();
        }

        private static IAuthorizationService NullService()
        {
            return null;
        }

        private static AuthorizationPolicy Policy()
        {
            return new AuthorizationPolicy(new[] {SingleRequirement()}, new[] {"scheme"});
        }

        private static object Resource()
        {
            return new object();
        }

        private static ClaimsPrincipal AnonymousUser()
        {
            return new ClaimsPrincipal();
        }

        private static IAuthorizationRequirement SingleRequirement()
        {
            return new AssertionRequirement(x => true);
        }
    }
}

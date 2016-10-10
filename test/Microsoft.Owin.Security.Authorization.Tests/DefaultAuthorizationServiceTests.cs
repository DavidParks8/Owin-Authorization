using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationServiceTests : TestClassBase
    {
        private class DynamicPolicyProvider : IAuthorizationPolicyProvider
        {
            public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
            {
                return Task.FromResult(new AuthorizationPolicyBuilder().RequireClaim(policyName).Build());
            }

            public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
            {
                throw new NotImplementedException();
            }
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task CanUseDynamicPolicyProvider()
        {
            var authorizationService = CreateDynamicAuthorizationService();
            var id = new ClaimsIdentity();
            id.AddClaim(new Claim("1", "1"));
            id.AddClaim(new Claim("2", "2"));
            var user = new ClaimsPrincipal(id);

            Assert.IsFalse(await authorizationService.AuthorizeAsync(user, "0"));
            Assert.IsTrue(await authorizationService.AuthorizeAsync(user, "1"));
            Assert.IsTrue(await authorizationService.AuthorizeAsync(user, "2"));
            Assert.IsFalse(await authorizationService.AuthorizeAsync(user, "3"));
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationService", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenPolicyProviderIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationService(null, new IAuthorizationHandler[0]);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationService", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenHandlersIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationService(new DynamicPolicyProvider(), null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationService", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenContextFactoryIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationService(new DynamicPolicyProvider(), new IAuthorizationHandler[0], null, null, new DefaultAuthorizationEvaluator());
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationService", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenEvaluatorIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationService(new DynamicPolicyProvider(), new IAuthorizationHandler[0], null, new DefaultAuthorizationHandlerContextFactory(), null);
        }

        [TestMethod, UnitTest]
        public async Task AuthorizationServiceShouldAddPassThroughIfNotPresent()
        {
            var options = new AuthorizationOptions();
            var policyProvider = new DefaultAuthorizationPolicyProvider(options);
            var handler = Repository.Create<IAuthorizationHandler>();
            handler.Setup(x => x.HandleAsync(It.IsAny<AuthorizationHandlerContext>())).Returns(Task.FromResult(0));
            var requirement = handler.As<IAuthorizationRequirement>();
            var service = new DefaultAuthorizationService(policyProvider, Enumerable.Empty<IAuthorizationHandler>());
            
            // the next line should cause the requirement to be called as a handler if Passthrough is working
            var authorized = await service.AuthorizeAsync(CreateAnonymousUser(), null, new[] {requirement.Object});

            Assert.IsFalse(authorized, "authorized");
            handler.Verify(x => x.HandleAsync(It.IsAny<AuthorizationHandlerContext>()));
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncShouldThrowWhenRequirementsIsNull()
        {
            var service = CreateDynamicAuthorizationService();
            await service.AuthorizeAsync(CreateAnonymousUser(), new object(), (IEnumerable<IAuthorizationRequirement>) null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task AuthorizeAsyncShouldThrowWhenPolicyIsNull()
        {
            var service = CreateDynamicAuthorizationService();
            await service.AuthorizeAsync(CreateAnonymousUser(), new object(), (string)null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncShouldFailWhenUserIsNull()
        {
            var service = CreateDynamicAuthorizationService();
            var authorized = await service.AuthorizeAsync(null, new object(), Enumerable.Empty<IAuthorizationRequirement>());
            Assert.IsFalse(authorized, "authorized");
        }

        [TestMethod, UnitTest, ExpectedException(typeof(InvalidOperationException))]
        public async Task AuthorizeAsyncShouldThrowWhenPolicyIsNotFound()
        {
            var policyProvider = Repository.Create<IAuthorizationPolicyProvider>();
            policyProvider.Setup(x => x.GetPolicyAsync(It.IsAny<string>()))
                .Returns(Task.FromResult<AuthorizationPolicy>(null));
            var service = new DefaultAuthorizationService(policyProvider.Object, Enumerable.Empty<IAuthorizationHandler>());
            await service.AuthorizeAsync(CreateAnonymousUser(), null, "fake policy");
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncShouldLogUsersName()
        {
            var service = CreateDynamicAuthorizationService();
            var identity = Repository.Create<IIdentity>();
            identity.SetupAllProperties();
            identity.Setup(x => x.Name).Returns("baxter");
            var user = new ClaimsPrincipal(identity.Object);
            await service.AuthorizeAsync(user, null, Enumerable.Empty<IAuthorizationRequirement>());

            identity.Verify(x => x.Name, Times.AtLeast(2));
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncShouldRunWhenIdentityIsNotClaimsIdentity()
        {
            var service = CreateDynamicAuthorizationService();
            var identity = Repository.Create<IIdentity>();
            identity.SetupAllProperties();
            var user = new ClaimsPrincipal(identity.Object);
            var authorized = await service.AuthorizeAsync(user, null, Enumerable.Empty<IAuthorizationRequirement>());
            Assert.IsFalse(authorized, "authorized");
        }

        [TestMethod, UnitTest]
        public async Task AuthorizeAsyncShouldLogUserWhenNoDefaultNameClaimIsPresent()
        {
            var service = CreateDynamicAuthorizationService();
            var identity = Repository.Create<ClaimsIdentity>();
            identity.SetupAllProperties();
            identity.Setup(x => x.FindFirst(It.IsAny<string>())).Returns<string>(s =>
            {
                switch (s)
                {
                    case "sub":
                    case ClaimTypes.Name:
                        return null;
                    default:
                        return new Claim("name", "baxter");
                }
            });

            var user = new ClaimsPrincipal(identity.Object);
            var authorized = await service.AuthorizeAsync(user, null, Enumerable.Empty<IAuthorizationRequirement>());
            Assert.IsFalse(authorized, "authorized");

            identity.Verify(x => x.FindFirst("sub"), Times.Once);
            identity.Verify(x => x.FindFirst(ClaimTypes.Name), Times.Once);
            identity.Verify(x => x.FindFirst(ClaimTypes.NameIdentifier), Times.Once);
        }

        private static ClaimsPrincipal CreateAnonymousUser()
        {
            return new ClaimsPrincipal();
        }

        private static DefaultAuthorizationService CreateDynamicAuthorizationService()
        {
            return new DefaultAuthorizationService(new DynamicPolicyProvider(), Enumerable.Empty<IAuthorizationHandler>());
        }
    }
}
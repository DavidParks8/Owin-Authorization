using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationHelperTests : TestClassBase
    {
        private const string s_nameClaimType = "name";
        private const string s_roleClaimType = "role";

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.AuthorizationHelper", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenContextAccessorIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationHelper(null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task IsAuthorizedAsyncShouldThrowWhenUserIsNull()
        {
            var helper = CreateHelperWithOptionsEmbedded(null);

            var controller = Repository.Create<IAuthorizationController>();
            var attributeData = Repository.Create<IAuthorizeData>();
            await helper.IsAuthorizedAsync(controller.Object, null, attributeData.Object);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task IsAuthorizedAsyncShouldThrowWhenAuthorizeAttributeIsNull()
        {
            var helper = CreateHelperWithOptionsEmbedded(null);

            var controller = Repository.Create<IAuthorizationController>();
            var user = CreateAnonymousUser();
            await helper.IsAuthorizedAsync(controller.Object, user, null);
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldThrowWhenAuthorizationOptionsIsNull()
        {
            var helper = CreateHelperWithOptionsEmbedded(null);

            var user = CreateAnonymousUser();
            var attributeData = Repository.Create<IAuthorizeData>();
            try
            {
                await helper.IsAuthorizedAsync(null, user, attributeData.Object);
                FailWhenNoExceptionIsThrown();
            }
            catch (InvalidOperationException exception)
            {
                Assert.AreEqual(Properties.Resources.Exception_AuthorizationOptionsMustNotBeNull, exception.Message);
            }
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldUseOptionsFromControllerBeforeOptionsFromOwinContext()
        {
            // this test sets up two different authorization options which require different role types, 
            // then makes sure the correct role type is authorized
            
            const string policyName = "policy";

            const string owinRole = "owin";
            var owinOptions = CreateOptionsWithRequiredRole(policyName, owinRole);

            const string controllerRole = "controller";
            var controllerOptions = CreateOptionsWithRequiredRole(policyName, controllerRole);

            var helper = CreateHelperWithOptionsEmbedded(owinOptions);

            var controller = Repository.Create<IAuthorizationController>();
            controller.Setup(x => x.AuthorizationOptions).Returns(controllerOptions);

            // create a user with the controller role
            var user = CreateAuthenticatedUser();
            user.Identities.First().AddClaim(new Claim(s_roleClaimType, controllerRole));

            // make an attribute with the policy name we set up earlier
            var attribute = Repository.Create<IAuthorizeData>();
            attribute.SetupAllProperties();
            attribute.Setup(x => x.Policy).Returns(policyName);

            var authorized = await helper.IsAuthorizedAsync(controller.Object, user, attribute.Object);
            Assert.IsTrue(authorized, "authorized");
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldInitializeDependencyFactory()
        {
            await AssertEverythingIsInitialized(null);
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldInitializeDependencies()
        {
            var dependenciesFactory = CreateDependenciesFactoryWithSpecificReturn(null);
            await AssertEverythingIsInitialized(dependenciesFactory.Object);
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldInitializeDependencyProperties()
        {
            var dependenciesFactory = CreateDependenciesFactoryWithSpecificReturn(new AuthorizationDependencies
            {
                HandlerProvider = null,
                LoggerFactory = null,
                PolicyProvider = null,
                ServiceFactory = null
            });

            await AssertEverythingIsInitialized(dependenciesFactory.Object);
            dependenciesFactory.Verify(x => x.Create(It.IsNotNull<AuthorizationOptions>(), It.IsNotNull<IOwinContext>()), Times.Once);
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldInitializeAuthorizationService()
        {
            var serviceFactory = Repository.Create<IAuthorizationServiceFactory>();
            serviceFactory.Setup(x => x.Create(
                It.IsAny<IAuthorizationPolicyProvider>(),
                It.IsAny<IEnumerable<IAuthorizationHandler>>(),
                It.IsAny<ILoggerFactory>(),
                It.IsAny<IAuthorizationEvaluator>()))
                .Returns((IAuthorizationService)null);

            var dependenciesFactory = CreateDependenciesFactoryWithSpecificReturn(new AuthorizationDependencies
            {
                HandlerProvider = null,
                LoggerFactory = null,
                PolicyProvider = null,
                ServiceFactory = serviceFactory.Object
            });

            await AssertEverythingIsInitialized(dependenciesFactory.Object);
        }

        private Mock<IAuthorizationDependenciesFactory> CreateDependenciesFactoryWithSpecificReturn(AuthorizationDependencies dependencies)
        {
            var dependenciesFactory = Repository.Create<IAuthorizationDependenciesFactory>();
            dependenciesFactory
                .Setup(x => x.Create(It.IsAny<AuthorizationOptions>(), It.IsAny<IOwinContext>()))
                .Returns(dependencies);
            return dependenciesFactory;
        }

        private async Task AssertEverythingIsInitialized(IAuthorizationDependenciesFactory dependenciesFactory)
        {
            var options = new AuthorizationOptions { DependenciesFactory = dependenciesFactory };
            var helper = CreateHelperWithOptionsEmbedded(options);

            var user = CreateAuthenticatedUser();
            var attributeData = Repository.Create<IAuthorizeData>();
            attributeData.SetupAllProperties();

            var authorized = await helper.IsAuthorizedAsync(null, user, attributeData.Object);
            Assert.IsTrue(authorized, "authorized");
        }

        private static AuthorizationOptions CreateOptionsWithRequiredRole(string policyName, string role)
        {
            var options = new AuthorizationOptions();
            options.AddPolicy(policyName, builder =>
            {
                builder.RequireRole(role);
            });

            return options;
        }

        private static ClaimsPrincipal CreateAuthenticatedUser()
        {
            return new ClaimsPrincipal(new ClaimsIdentity(new Claim[0], "authenticated", s_nameClaimType, s_roleClaimType));
        }

        private static ClaimsPrincipal CreateAnonymousUser()
        {
            return new ClaimsPrincipal();
        }

        private Mock<IOwinContextAccessor> CreateAccessorWithOptionsEmbedded(AuthorizationOptions options)
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object> {{ResourceAuthorizationMiddleware.ServiceKey, options}};
            owinContext.Setup(x => x.Environment).Returns(environment);
            var accessor = Repository.Create<IOwinContextAccessor>();
            accessor.Setup(x => x.Context).Returns(owinContext.Object);
            return accessor;
        }

        private AuthorizationHelper CreateHelperWithOptionsEmbedded(AuthorizationOptions options)
        {
            var accessor = CreateAccessorWithOptionsEmbedded(options);
            return new AuthorizationHelper(accessor.Object);
        }
    }
}

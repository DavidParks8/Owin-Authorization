using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationHelperTests : TestClassBase
    {
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenContextAccessorIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationHelper(null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task IsAuthorizedAsyncShouldThrowWhenUserIsNull()
        {
            var contextAccessor = Repository.Create<IOwinContextAccessor>();
            var helper = new AuthorizationHelper(contextAccessor.Object);

            var controller = Repository.Create<IAuthorizationController>();
            var attributeData = Repository.Create<IAuthorizeData>();
            await helper.IsAuthorizedAsync(controller.Object, null, attributeData.Object);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task IsAuthorizedAsyncShouldThrowWhenAuthorizeAttributeIsNull()
        {
            var contextAccessor = Repository.Create<IOwinContextAccessor>();
            var helper = new AuthorizationHelper(contextAccessor.Object);

            var controller = Repository.Create<IAuthorizationController>();
            var user = new ClaimsPrincipal();
            await helper.IsAuthorizedAsync(controller.Object, user, null);
        }

        [TestMethod, UnitTest]
        public async Task IsAuthorizedAsyncShouldThrowWhenAuthorizationOptionsIsNull()
        {
            var contextAccessor = CreateAccessorWithOptionsEmbedded(null);
            var helper = new AuthorizationHelper(contextAccessor.Object);

            var user = new ClaimsPrincipal();
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

        private Mock<IOwinContextAccessor> CreateAccessorWithOptionsEmbedded(AuthorizationOptions options)
        {
            var owinContext = Repository.Create<IOwinContext>();
            var environment = new Dictionary<string, object> {{ResourceAuthorizationMiddleware.ServiceKey, options}};
            owinContext.Setup(x => x.Environment).Returns(environment);
            var accessor = Repository.Create<IOwinContextAccessor>();
            accessor.Setup(x => x.Context).Returns(owinContext.Object);
            return accessor;
        }
    }
}

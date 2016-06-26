using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization.Mvc
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ResourceAuthorizeAttributeTests : TestClassBase
    {
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void OnAuthorizationShouldThrowWhenFilterContextIsNull()
        {
            var attribute = new ResourceAuthorizeAttribute();
            attribute.OnAuthorization(null);
        }

        private sealed class TestAuthorize : ResourceAuthorizeAttribute
        {
            public void PassNullToAuthorizeCore()
            {
                AuthorizeCore(null);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AuthorizeCoreShouldThrowWhenHttpContextBaseIsNull()
        {
            new TestAuthorize().PassNullToAuthorizeCore();
        }

        [TestMethod, UnitTest]
        public void UserShouldNotBeAuthorized()
        {
            var options = new AuthorizationOptions();
            var controller = Repository.Create<ControllerBase>();
            controller.As<IAuthorizationController>().Setup(x => x.AuthorizationOptions).Returns(options);

            var authorizationContext = new System.Web.Mvc.AuthorizationContext
            {
                HttpContext = SetupHttpContextBase().Object,
                ActionDescriptor = SetupAllowAnonymous(false).Object,
                Controller = controller.Object
            };

            var attribute = new ResourceAuthorizeAttribute();
            attribute.OnAuthorization(authorizationContext);
            Assert.IsInstanceOfType(authorizationContext.Result, typeof(HttpUnauthorizedResult));
        }

        private Mock<ActionDescriptor> SetupAllowAnonymous(bool attributePresent)
        {
            var action = Repository.Create<ActionDescriptor>();
            action.Setup(x => x.IsDefined(It.IsAny<Type>(), It.IsAny<bool>())).Returns(attributePresent);
            action.Setup(x => x.ControllerDescriptor.IsDefined(It.IsAny<Type>(), It.IsAny<bool>())).Returns(attributePresent);
            return action;
        }

        private Mock<HttpContextBase> SetupHttpContextBase()
        {
            var user = new ClaimsPrincipal();
            var items = new Hashtable { { "owin.Environment", new Dictionary<string, object>() } };

            var httpContextBase = Repository.Create<HttpContextBase>();
            httpContextBase.Setup(x => x.User).Returns(user);
            httpContextBase.Setup(x => x.Items).Returns(items);
            return httpContextBase;
        }

        [TestMethod, UnitTest]
        public void RolesShouldAllowSet()
        {
            AssertSetterSets(nameof(ResourceAuthorizeAttribute.Roles));
        }

        [TestMethod, UnitTest]
        public void PolicyShouldAllowSet()
        {
            AssertSetterSets(nameof(ResourceAuthorizeAttribute.Policy));
        }

        [TestMethod, UnitTest]
        public void SchemesShouldAllowSet()
        {
            AssertSetterSets(nameof(ResourceAuthorizeAttribute.ActiveAuthenticationSchemes));
        }

        private static void AssertSetterSets(string propertyName)
        {
            const string test = "test";
            var property = typeof(ResourceAuthorizeAttribute).GetProperty(propertyName);
            Assert.AreEqual(typeof(string), property.PropertyType);
            var attribute = new ResourceAuthorizeAttribute();
            var initialPropertyValue = (string)property.GetValue(attribute);
            Assert.IsTrue(string.IsNullOrWhiteSpace(initialPropertyValue));
            property.SetValue(attribute, test);
            var newPropertyValue = property.GetValue(attribute);
            Assert.AreEqual(test, newPropertyValue);
        }
    }
}

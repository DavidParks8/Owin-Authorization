using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization.WebApi
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
            public void PassNullIntoIsAuthorized()
            {
                IsAuthorized(null);
            }
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void IsAuthorizedShouldThrowWhenActionContextIsNull()
        {
            new TestAuthorize().PassNullIntoIsAuthorized();
        }

        [TestMethod, UnitTest]
        public void UserShouldNotBeAuthorized()
        {
            var user = new ClaimsPrincipal();

            var options = new AuthorizationOptions();
            var controller = Repository.Create<IHttpController>();
            controller.As<IAuthorizationController>().Setup(x => x.AuthorizationOptions).Returns(options);
            using (var request = new HttpRequestMessage())
            {
                request.Properties.Add("MS_OwinEnvironment", new Dictionary<string, object>());
                var anonymousAttributes = new Collection<AllowAnonymousAttribute>();
                var controllerDescriptor = Repository.Create<HttpControllerDescriptor>();
                controllerDescriptor.Setup(x => x.GetCustomAttributes<AllowAnonymousAttribute>()).Returns(anonymousAttributes);
                var controllerContext = new HttpControllerContext
                {
                    Controller = controller.Object,
                    Request = request,
                    RequestContext = new HttpRequestContext { Principal = user },
                    ControllerDescriptor = controllerDescriptor.Object
                };

                var actionContext = new HttpActionContext { ControllerContext = controllerContext };
                var action = Repository.Create<HttpActionDescriptor>();
                action.Setup(x => x.GetCustomAttributes<AllowAnonymousAttribute>()).Returns(anonymousAttributes);
                actionContext.ActionDescriptor = action.Object;
                var attribute = new ResourceAuthorizeAttribute();
                attribute.OnAuthorization(actionContext);
                try
                {
                    Assert.AreEqual(HttpStatusCode.Unauthorized, actionContext.Response.StatusCode);
                }
                finally
                {
                    actionContext.Response?.Dispose();
                }
                
            }
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
            Assert.IsTrue(string.IsNullOrWhiteSpace(initialPropertyValue), "string.IsNullOrWhiteSpace(initialPropertyValue)");
            property.SetValue(attribute, test);
            var newPropertyValue = property.GetValue(attribute);
            Assert.AreEqual(test, newPropertyValue);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Owin;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AppBuilderExtensionsTests : TestClassBase
    {
        private static ParameterInfo GetNullParameter(int parameterPosition, params Type[] functionArguments)
        {
            Assert.IsTrue(parameterPosition > -1);
            Assert.IsNotNull(functionArguments);

            var method = typeof(AppBuilderExtensions)
                .GetMethods()
                .FirstOrDefault(m =>
                {
                    if (m.Name != nameof(AppBuilderExtensions.UseAuthorization))
                    {
                        return false;
                    }
                    // deal with optional parameters
                    for (var i = 0; i < functionArguments.Length; i++)
                    {
                        if (m.GetParameters().Length <= i)
                        {
                            return false;
                        }
                        if (m.GetParameters()[i].ParameterType != functionArguments[i])
                        {
                            return false;
                        }
                    }
                    return true;
                });
            if (method == null)
            {
                Assert.Fail("method signature not found");
            }
            var parameter = method.GetParameters()[parameterPosition];
            return parameter;
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithNoArgsThrowsWhenAppBuilderIsNull()
        {
            try
            {
                AppBuilderExtensions.UseAuthorization(null);
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(0, typeof(IAppBuilder));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsArgThrowsWhenAppBuilderIsNull()
        {
            try
            {
                AppBuilderExtensions.UseAuthorization(null, new AuthorizationOptions());
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(0, typeof(IAppBuilder), typeof(AuthorizationOptions));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsActionArgThrowsWhenAppBuilderIsNull()
        {
            try
            {
                AppBuilderExtensions.UseAuthorization(null, options => {});
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(0, typeof(IAppBuilder), typeof(Action<AuthorizationOptions>));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsArgThrowsWhenOptionsIsNull()
        {
            try
            {
                Repository.Create<IAppBuilder>().Object.UseAuthorization((AuthorizationOptions)null);
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(1, typeof(IAppBuilder), typeof(AuthorizationOptions));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsActionArgThrowsWhenActionIsNull()
        {
            try
            {
                var app = Repository.Create<IAppBuilder>(MockBehavior.Loose);
                app.Setup(a => a.Properties).Returns(new Dictionary<string, object>());
                app.Object.UseAuthorization((Action<AuthorizationOptions>)null);
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(1, typeof(IAppBuilder), typeof(Action<AuthorizationOptions>));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithNoArgsConstructsOptions()
        {
            var app = Repository.Create<IAppBuilder>(MockBehavior.Loose);
            app.Setup(a => a.Properties).Returns(new Dictionary<string, object>());
            app.Object.UseAuthorization();
            app.Verify(x => x.Use(typeof(ResourceAuthorizationMiddleware), It.IsNotNull<AuthorizationOptions>()), Times.Once);
        }
    }
}

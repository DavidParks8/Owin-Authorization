using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
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

            var method = typeof(AppBuilderExtensions).GetMethod(nameof(AppBuilderExtensions.UseAuthorization), functionArguments);
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
                Repository.Create<IAppBuilder>().Object.UseAuthorization((Action<AuthorizationOptions>)null);
                FailWhenNoExceptionIsThrown();
            }
            catch (ArgumentNullException exception)
            {
                var parameter = GetNullParameter(1, typeof(IAppBuilder), typeof(Action<AuthorizationOptions>));
                Assert.AreEqual(parameter.Name, exception.ParamName);
            }
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsArgShouldInitializeNullDependencies()
        {
            var options = new AuthorizationOptions { Dependencies = null };
            var app = Repository.Create<IAppBuilder>(MockBehavior.Loose);
            app.Object.UseAuthorization(options);

            Assert.IsNotNull(options.Dependencies, "options.Dependencies != null");
            Assert.IsNotNull(options.Dependencies.LoggerFactory, "options.Dependencies.LoggerFactory != null");
            Assert.IsNotNull(options.Dependencies.Service, "options.Dependencies.Service != null");
            Assert.IsInstanceOfType(options.Dependencies.Service, typeof(DefaultAuthorizationService), "Default authorization service was not set");

            app.Verify(x => x.Use(typeof(ResourceAuthorizationMiddleware), options), Times.Once);
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithNoArgsConstructsOptions()
        {
            var app = Repository.Create<IAppBuilder>(MockBehavior.Loose);
            app.Object.UseAuthorization();
            app.Verify(x => x.Use(typeof(ResourceAuthorizationMiddleware), It.IsNotNull<AuthorizationOptions>()), Times.Once);
        }

        [TestMethod, UnitTest]
        public void UseAuthorizationWithOptionsActionArgRunsAction()
        {
            var actionRan = false;
            var app = Repository.Create<IAppBuilder>(MockBehavior.Loose);
            app.Object.UseAuthorization(options =>
            {
                actionRan = true;
                Assert.IsNotNull(options, "options != null");
                Assert.IsNotNull(options.Dependencies, "options.Dependencies != null");
            });

            app.Verify(x => x.Use(typeof(ResourceAuthorizationMiddleware), It.IsNotNull<AuthorizationOptions>()), Times.Once);
            Assert.IsTrue(actionRan, "The action did not run");
        }
    }
}

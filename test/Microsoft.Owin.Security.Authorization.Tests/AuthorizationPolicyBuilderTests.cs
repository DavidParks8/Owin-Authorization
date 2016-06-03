using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationPolicyBuilderTests
    {
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddAuthenticationSchemesShouldThrowWhenShemesIsNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            string[] nullSchemes = null;
            // ReSharper disable once ExpressionIsAlwaysNull
            builder.AddAuthenticationSchemes(nullSchemes);
        }

        [TestMethod, UnitTest]
        public void AddAuthenticationSchemesShouldSucceed()
        {
            var schemes = new[]
            {
                "test1", "test2", "test3"
            };

            var builder = new AuthorizationPolicyBuilder();
            builder.AddAuthenticationSchemes(schemes);
            Assert.AreEqual(schemes.Length, builder.AuthenticationSchemes.Count);
            for (var i = 0; i < schemes.Length; i++)
            {
                Assert.AreEqual(schemes[i], builder.AuthenticationSchemes[i]);
            }
        }

        [TestMethod, UnitTest]
        public void AuthenticationSchemesShouldBeEmptyOnConstruction()
        {
            var builder = new AuthorizationPolicyBuilder();
            Assert.AreEqual(0, builder.AuthenticationSchemes.Count);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddRequirementsShouldThrowWhenRequirementsIsNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            IAuthorizationRequirement[] requirements = null;
            // ReSharper disable once ExpressionIsAlwaysNull
            builder.AddRequirements(requirements);
        }

        [TestMethod, UnitTest]
        public void AddRequirementsShouldSucceed()
        {
            var requirements = new IAuthorizationRequirement[]
            {
                new ClaimsAuthorizationRequirement("test", new []{ "test" }),
                new RolesAuthorizationRequirement(new [] { "role" })  
            };

            var builder = new AuthorizationPolicyBuilder();
            builder.AddRequirements(requirements);
            Assert.AreEqual(requirements.Length, builder.Requirements.Count);
            for (var i = 0; i < requirements.Length; i++)
            {
                Assert.AreEqual(requirements[i], builder.Requirements[i]);
            }
        }

        [TestMethod, UnitTest]
        public void RequirementsShouldBeEmptyOnConstruction()
        {
            var builder = new AuthorizationPolicyBuilder();
            Assert.AreEqual(0, builder.Requirements.Count);
        }

        [TestMethod, UnitTest]
        public void AuthenticationSchemesShouldNotBeNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            Assert.IsNotNull(builder.AuthenticationSchemes, "builder.AuthenticationSchemes != null");
        }

        [TestMethod, UnitTest]
        public void AuthenticationSchemesShouldHaveNoSetter()
        {
            var property = typeof(AuthorizationPolicyBuilder).GetProperty(nameof(AuthorizationPolicyBuilder.AuthenticationSchemes));
            Assert.IsFalse(property.CanWrite, "property.CanWrite");
        }

        [TestMethod, UnitTest]
        public void RequirementsShouldNotBeNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            Assert.IsNotNull(builder.Requirements, "builder.Requirements != null");
        }

        [TestMethod, UnitTest]
        public void RequirementsShouldHaveNoSetter()
        {
            var property = typeof(AuthorizationPolicyBuilder).GetProperty(nameof(AuthorizationPolicyBuilder.Requirements));
            Assert.IsFalse(property.CanWrite, "property.CanWrite");
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CombineShouldThrowWhenPolicyIsNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            builder.Combine(null);
        }

        [TestMethod, UnitTest]
        public void ConstructorShouldCombinePolicy()
        {
            AssertCombineSuccess(policy => new AuthorizationPolicyBuilder(policy));
        }

        [TestMethod, UnitTest]
        public void CombineShouldSucceed()
        {
            AssertCombineSuccess(policy =>
            {
                var builder = new AuthorizationPolicyBuilder();
                builder.Combine(policy);
                return builder;
            });
        }

        private static void AssertCombineSuccess(Func<AuthorizationPolicy, AuthorizationPolicyBuilder> testFunc)
        {
            var requirements = new IAuthorizationRequirement[]
            {
                new DenyAnonymousAuthorizationRequirement()
            };
            var schemes = new[] { "test" };

            var policy = new AuthorizationPolicy(requirements, schemes);
            var builder = testFunc(policy);


            Assert.AreEqual(requirements.Length, builder.Requirements.Count);
            Assert.AreSame(requirements[0], builder.Requirements[0]);
            Assert.AreEqual(schemes.Length, builder.AuthenticationSchemes.Count);
            Assert.AreEqual(schemes[0], builder.AuthenticationSchemes[0]);
        }

        [TestMethod, UnitTest]
        public void RequireAuthenticatedUserShouldAddDenyRequirement()
        {
            var builder = new AuthorizationPolicyBuilder();
            builder.RequireAuthenticatedUser();
            Assert.IsInstanceOfType(builder.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void RequireUserNameShouldThrowWhenUserNameIsNull()
        {
            var builder = new AuthorizationPolicyBuilder();
            builder.RequireUserName(null);
        }

        [TestMethod, UnitTest]
        public void RequireUserNameShouldAddNameRequirement()
        {
            const string testName = "test";
            var builder = new AuthorizationPolicyBuilder();
            builder.RequireUserName(testName);
            Assert.IsInstanceOfType(builder.Requirements[0], typeof(NameAuthorizationRequirement));
            Assert.AreEqual(testName, ((NameAuthorizationRequirement)builder.Requirements[0]).RequiredName);
        }
    }
}

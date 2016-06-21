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
    public class AuthorizationOptionsTests
    {
        private static AuthorizationOptions NewOptions()
        {
            return new AuthorizationOptions();
        }

        private static AuthorizationPolicy NewPolicy()
        {
            return new AuthorizationPolicy(new List<IAuthorizationRequirement>() { new DenyAnonymousAuthorizationRequirement() }, new List<string>());
        }

        [TestMethod, UnitTest]
        public void DefaultPolicyShouldRequireAuthenticatedUser()
        {
            var options = NewOptions();
            var requirement = options.DefaultPolicy.Requirements.First();
            Assert.IsInstanceOfType(requirement, typeof(DenyAnonymousAuthorizationRequirement));
        }

        [TestMethod, UnitTest]
        public void DefaultPolicyShouldBeSettable()
        {
            var options = NewOptions();
            options.DefaultPolicy = null;
            Assert.IsNull(options.DefaultPolicy);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddPolicyShouldThrowWhenNameIsNull()
        {
            var options = NewOptions();
            options.AddPolicy(null, NewPolicy());
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddPolicyShouldThrowWhenPolicyIsNull()
        {
            var options = NewOptions();
            options.AddPolicy("asdf", (AuthorizationPolicy)null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddPolicyActionShouldThrowWhenNameIsNull()
        {
            var options = NewOptions();
            options.AddPolicy(null, x => {});
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void AddPolicyActionShouldThrowWhenActionIsNull()
        {
            var options = NewOptions();
            options.AddPolicy("asdf", (Action<AuthorizationPolicyBuilder>)null);
        }

        [TestMethod, UnitTest]
        public void AddPolicyShouldAddAPolicy()
        {
            var options = NewOptions();
            var policy = NewPolicy();
            const string policyName = "asdf";
            options.AddPolicy(policyName, policy);
            var foundPolicy = options.GetPolicy(policyName);
            Assert.AreSame(policy, foundPolicy);
        }

        [TestMethod, UnitTest]
        public void AddPolicyActionShouldAddAPolicy()
        {
            var options = NewOptions();
            const string policyName = "asdf";
            options.AddPolicy(policyName, builder => builder.RequireAuthenticatedUser());
            var foundPolicy = options.GetPolicy(policyName);
            Assert.IsInstanceOfType(foundPolicy.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void GetPolicyShouldThrowWhenNameIsNull()
        {
            var options = NewOptions();
            options.GetPolicy(null);
        }

        [TestMethod, UnitTest]
        public void GetPolicyShouldReturnNullWhenNoPolicyIsFound()
        {
            var options = NewOptions();
            var policy = options.GetPolicy("asdf");
            Assert.IsNull(policy);
        }
    }
}

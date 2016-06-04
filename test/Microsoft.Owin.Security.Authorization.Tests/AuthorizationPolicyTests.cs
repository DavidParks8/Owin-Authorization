using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationPolicyTests
    {
        private const string _messageId = "Microsoft.Owin.Security.Authorization." + nameof(AuthorizationPolicy);

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenRequirementsIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationPolicy(null, new string[0]);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenAuthenticationSchemesIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationPolicy(new IAuthorizationRequirement[0], null);
        }

        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = _messageId, Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(InvalidOperationException))]
        public void ConstructorShouldThrowWhenRequirementsIsEmpty()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationPolicy(new IAuthorizationRequirement[0], new string[0]);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CombineShouldThrowWhenPoliciesParametersIsNull()
        {
            AuthorizationPolicy[] policies = null;
            // ReSharper disable once ExpressionIsAlwaysNull because we want it to be null
            AuthorizationPolicy.Combine(policies);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CombineShouldThrowWhenPoliciesEnumerableIsNull()
        {
            AuthorizationPolicy.Combine((IEnumerable<AuthorizationPolicy>)null);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CombineShouldThrowWhenOptionsIsNull()
        {
            AuthorizationPolicy.Combine(null, new IAuthorizeData[0]);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void CombineShouldThrowWhenAttributesIsNull()
        {
            AuthorizationPolicy.Combine(new AuthorizationOptions(), null);
        }

        [TestMethod, UnitTest]
        public void PoliciesShouldCombine()
        {
            const string allowedRole = "test role";
            var roleRequirement = new RolesAuthorizationRequirement(new[] {allowedRole});
            var rolePolicy = new AuthorizationPolicy(new [] { roleRequirement }, new string[0]);

            var denyAnonymousRequirement = new DenyAnonymousAuthorizationRequirement();
            var denyAnonymousPolicy = new AuthorizationPolicy(new []{denyAnonymousRequirement}, new string[0]);

            var combinedPolicy = AuthorizationPolicy.Combine(rolePolicy, denyAnonymousPolicy);
            var requirements = new HashSet<IAuthorizationRequirement>(combinedPolicy.Requirements);
            Assert.IsTrue(requirements.Contains(roleRequirement));
            Assert.IsTrue(requirements.Contains(denyAnonymousRequirement));
        }

        [TestMethod, UnitTest]
        public void CombineShouldReturnNullWhenThereAreNoAttributes()
        {
            var policy = AuthorizationPolicy.Combine(new AuthorizationOptions(), new IAuthorizeData[0]);
            Assert.IsNull(policy, "policy != null");
        }
    }
}

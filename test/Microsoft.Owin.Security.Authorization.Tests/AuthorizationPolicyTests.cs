using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationPolicyTests : TestClassBase
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
        public async Task CombineShouldThrowWhenOptionsIsNull()
        {
            await AuthorizationPolicy.CombineAsync(null, new IAuthorizeData[0]);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task CombineShouldThrowWhenAttributesIsNull()
        {
            await AuthorizationPolicy.CombineAsync(new DefaultAuthorizationPolicyProvider(new AuthorizationOptions()), null);
        }

        [TestMethod, UnitTest]
        public void PoliciesShouldCombine()
        {
            const string allowedRole = "test role";
            var roleRequirement = new RolesAuthorizationRequirement(new[] { allowedRole });
            var rolePolicy = new AuthorizationPolicy(new[] { roleRequirement }, new string[0]);

            var denyAnonymousRequirement = new DenyAnonymousAuthorizationRequirement();
            var denyAnonymousPolicy = new AuthorizationPolicy(new[] { denyAnonymousRequirement }, new string[0]);

            var combinedPolicy = AuthorizationPolicy.Combine(rolePolicy, denyAnonymousPolicy);
            var requirements = new HashSet<IAuthorizationRequirement>(combinedPolicy.Requirements);
            Assert.IsTrue(requirements.Contains(roleRequirement));
            Assert.IsTrue(requirements.Contains(denyAnonymousRequirement));
        }

        [TestMethod, UnitTest]
        public async Task CombineShouldReturnNullWhenThereAreNoAttributes()
        {
            var policy = await AuthorizationPolicy.CombineAsync(new DefaultAuthorizationPolicyProvider(new AuthorizationOptions()), new IAuthorizeData[0]);
            Assert.IsNull(policy, "policy != null");
        }

        private Mock<IAuthorizeData> CreateAndSetupData(string policy, string roles, string schemes)
        {
            var data = Repository.Create<IAuthorizeData>();
            data.Setup(x => x.Policy).Returns(policy);
            data.Setup(x => x.Roles).Returns(roles);
            data.Setup(x => x.ActiveAuthenticationSchemes).Returns(schemes);
            return data;
        }

        private static Task<AuthorizationPolicy> CombineWithOptionsAsync(params Mock<IAuthorizeData>[] data)
        {
            return CombineWithOptionsAsync(new AuthorizationOptions(), data);
        }

        private static Task<AuthorizationPolicy> CombineWithOptionsAsync(AuthorizationOptions options, params Mock<IAuthorizeData>[] data)
        {
            var attributes = new IAuthorizeData[data.Length];
            for (var i = 0; i < attributes.Length; i++)
            {
                attributes[i] = data[i].Object;
            }

            return AuthorizationPolicy.CombineAsync(new DefaultAuthorizationPolicyProvider(options), attributes);
        }

        private static AuthorizationOptions CreateOptionsAndAddPolicy(string policyName, AuthorizationPolicy policy)
        {
            var options = new AuthorizationOptions();
            options.AddPolicy(policyName, policy);
            return options;
        }

        private static AuthorizationPolicy CreateAssertionPolicy(params string[] schemes)
        {
            return new AuthorizationPolicy(new[] { new AssertionRequirement(x => true) }, schemes);
        }

        [TestMethod, UnitTest, ExpectedException(typeof(InvalidOperationException))]
        public async Task CombineShouldThrowWhenNoPolicyIsFound()
        {
            var data = CreateAndSetupData("policy name", null, null);
            await CombineWithOptionsAsync(data);
        }

        [TestMethod, UnitTest]
        public async Task CombineShouldUseDefaultPolicyAsDefault()
        {
            var data = CreateAndSetupData(null, null, null);
            var policy = CreateAssertionPolicy();
            var options = new AuthorizationOptions() { DefaultPolicy = policy };
            var combined = await CombineWithOptionsAsync(options, data);
            Assert.IsInstanceOfType(combined.Requirements[0], typeof(AssertionRequirement));
        }

        [TestMethod, UnitTest]
        public async Task CombineShouldCombinePolicy()
        {
            const string policyName = "policy name";
            const string scheme = "authentication scheme";
            var data = CreateAndSetupData(policyName, null, null);
            var policy = CreateAssertionPolicy(scheme);
            var options = CreateOptionsAndAddPolicy(policyName, policy);
            var combined = await CombineWithOptionsAsync(options, data);

            Assert.IsInstanceOfType(combined.Requirements[0], typeof(AssertionRequirement));
            Assert.AreEqual(scheme, combined.AuthenticationSchemes[0]);
        }

        private static async Task AssertDefaultIsIgnoredAsync(AuthorizationOptions options, Mock<IAuthorizeData> data)
        {
            Assert.IsNotNull(options, "options != null");
            Assert.IsNotNull(data, "data != null");

            var combined = await CombineWithOptionsAsync(options, data);

            Assert.AreEqual(1, combined.Requirements.Count);
            Assert.IsNotInstanceOfType(combined.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }

        [TestMethod, UnitTest]
        public async Task CombinePolicyShouldIgnoreDefaultPolicy()
        {
            const string policyName = "policy name";
            var data = CreateAndSetupData(policyName, null, null);
            var policy = CreateAssertionPolicy();
            var options = CreateOptionsAndAddPolicy(policyName, policy);

            await AssertDefaultIsIgnoredAsync(options, data);
        }

        [TestMethod, UnitTest]
        public async Task CombineRolesShouldIgnoreDefaultPolicy()
        {
            await AssertDefaultIsIgnoredAsync(new AuthorizationOptions(), CreateAndSetupData(null, "role", null));
        }

        [TestMethod, UnitTest]
        public async Task CombineSchemesShouldIgnoreDefaultPolicy()
        {
            var options = new AuthorizationOptions { DefaultPolicy = null };
            var combined = await CombineWithOptionsAsync(options, CreateAndSetupData(null, null, "scheme"));

            Assert.AreEqual(1, combined.Requirements.Count);
            Assert.IsInstanceOfType(combined.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }

        private static void AssertListsEqual<T>(IReadOnlyList<T> first, IReadOnlyList<T> second)
        {
            Assert.AreEqual(first.Count, second.Count);
            for (var i = 0; i < first.Count; i++)
            {
                Assert.AreEqual(first[i], second[i]);
            }
        }

        private static void AssertCorrectRoles(IReadOnlyList<string> expected, AuthorizationPolicy policy, int index = 0)
        {
            var roleRequirement = (RolesAuthorizationRequirement)policy.Requirements[index];
            AssertListsEqual(expected, roleRequirement.AllowedRoles.ToArray());
        }

        private static void AssertCorrectSchemes(IReadOnlyList<string> expected, AuthorizationPolicy policy)
        {
            AssertListsEqual(expected, policy.AuthenticationSchemes);
        }

        [TestMethod, UnitTest]
        public async Task CombineRolesShouldBeSplitByComma()
        {
            var roles = new[] { "role1", "role2" };
            var data = CreateAndSetupData(null, string.Join(",", roles), null);
            var combined = await CombineWithOptionsAsync(data);

            AssertCorrectRoles(roles, combined);
        }

        [TestMethod, UnitTest]
        public async Task CombineSchemesShouldBeSplitByComma()
        {
            var schemes = new[] { "scheme1", "scheme2" };
            var data = CreateAndSetupData(null, null, string.Join(",", schemes));
            var combined = await CombineWithOptionsAsync(data);

            AssertCorrectSchemes(schemes, combined);
        }

        [TestMethod, UnitTest]
        public async Task CombineSchemesAloneShouldRequireAuthenticatedUser()
        {
            var data = CreateAndSetupData(null, null, "scheme");
            var combined = await CombineWithOptionsAsync(data);

            Assert.IsInstanceOfType(combined.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }

        [TestMethod, UnitTest]
        public async Task CombineSchemesNotAloneShouldNotRequireAuthenticatedUser()
        {
            const string scheme = "scheme";
            var data = CreateAndSetupData(null, null, scheme);
            var otherData = CreateAndSetupData(null, "role", null);
            var combined = await CombineWithOptionsAsync(data, otherData);

            Assert.AreEqual(1, combined.Requirements.Count);
            Assert.IsNotInstanceOfType(combined.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
            AssertCorrectSchemes(new[] { scheme }, combined);
        }

        [TestMethod, UnitTest]
        public async Task CombineSplitShouldIgnoreEmptyEntries()
        {
            var data = CreateAndSetupData(null, null, ",test1,,,test2");
            var combined = await CombineWithOptionsAsync(data);

            AssertCorrectSchemes(new[] { "test1", "test2" }, combined);
        }

        [TestMethod, UnitTest]
        public async Task CombineSplitShouldTrimEntries()
        {
            var data = CreateAndSetupData(null, null, "  test1 \r\n ,     \ttest2");
            var combined = await CombineWithOptionsAsync(data);

            AssertCorrectSchemes(new[] { "test1", "test2" }, combined);
        }

        [TestMethod, UnitTest]
        public async Task CombineAllShouldSucceed()
        {
            const string policyName = "policy name";
            const string role = "role";
            const string scheme = "scheme";

            var policyData = CreateAndSetupData(policyName, null, null);
            var rolesData = CreateAndSetupData(null, role, null);
            var schemesData = CreateAndSetupData(null, null, scheme);

            var policy = CreateAssertionPolicy();
            var options = CreateOptionsAndAddPolicy(policyName, policy);
            var combined = await CombineWithOptionsAsync(options, policyData, rolesData, schemesData);

            Assert.IsInstanceOfType(combined.Requirements[0], typeof(AssertionRequirement));
            AssertCorrectRoles(new[] { role }, combined, 1);
            AssertCorrectSchemes(new[] { scheme }, combined);
        }


    }
}

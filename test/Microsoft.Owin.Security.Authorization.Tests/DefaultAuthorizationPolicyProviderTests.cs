using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationPolicyProviderTests : TestClassBase
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults",
            MessageId = "Microsoft.Owin.Security.Authorization." + nameof(DefaultAuthorizationPolicyProvider),
            Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenOptionsIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationPolicyProvider(null);
        }

        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = Justifications.MustBeInstanceMethod)]
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public async Task GetPolicyShouldThrowWhenPolicyNameIsNull()
        {
            var options = new AuthorizationOptions();
            var provider = new DefaultAuthorizationPolicyProvider(options);
            await provider.GetPolicyAsync(null);
        }

        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = Justifications.MustBeInstanceMethod)]
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task GetPolicyShouldReturnNullWhenThereAreNoPolicies()
        {
            var options = new AuthorizationOptions();
            var provider = new DefaultAuthorizationPolicyProvider(options);
            var policy = await provider.GetPolicyAsync("policy name");
            Assert.IsNull(policy);
        }

        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = Justifications.MustBeInstanceMethod)]
        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task GetPolicyShouldReturnAPolicy()
        {
            const string policyName = "policy name";
            var options = new AuthorizationOptions();
            options.AddPolicy(policyName, builder => builder.RequireAuthenticatedUser());
            var provider = new DefaultAuthorizationPolicyProvider(options);
            var policy = await provider.GetPolicyAsync(policyName);
            Assert.IsNotNull(policy, "policy != null");
            Assert.IsInstanceOfType(policy.Requirements[0], typeof(DenyAnonymousAuthorizationRequirement));
        }
    }
}

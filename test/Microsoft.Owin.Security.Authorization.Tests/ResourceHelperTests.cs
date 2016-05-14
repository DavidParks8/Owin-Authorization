using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ResourceHelperTests : TestClassBase
    {
        [TestMethod, UnitTest]
        public void EnsureAuthorizationPolicyNotFoundIsFormatted()
        {
            const string toReplace = "test string";
            var expected = string.Format(CultureInfo.CurrentCulture, Properties.Resources.Exception_AuthorizationPolicyNotFound, toReplace);
            var actual = Properties.ResourceHelper.FormatException_AuthorizationPolicyNotFound(toReplace);
            Assert.AreEqual(expected, actual);
        }
    }
}

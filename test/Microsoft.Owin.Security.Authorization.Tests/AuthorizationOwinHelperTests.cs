using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class AuthorizationOwinHelperTests
    {
        [TestMethod, ExpectedException(typeof(ArgumentNullException))]
        public void AuthorizationOwinHelperShouldThrowWhenPassedNullOwinContext()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new AuthorizationOwinHelper(null);
        }
    }
}

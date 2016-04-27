using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class ResourceAuthorizationAttributeTest
    {
        [TestMethod, ExpectedException(typeof(ArgumentNullException))]
        public void ResourceAuthorizeShouldThrowWhenPassedNull()
        {
            var attribute = new ResourceAuthorizeAttribute();
            attribute.OnAuthorization(null);
        }
    }
}

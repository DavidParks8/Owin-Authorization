// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationServiceTests
    {
        private class DynamicPolicyProvider : IAuthorizationPolicyProvider
        {
            public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
            {
                return Task.FromResult(new AuthorizationPolicyBuilder().RequireClaim(policyName).Build());
            }

            public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
            {
                throw new NotImplementedException();
            }
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task CanUseDynamicPolicyProvider()
        {
            var authorizationService = new DefaultAuthorizationService(new DynamicPolicyProvider(), Enumerable.Empty<IAuthorizationHandler>());

            var id = new ClaimsIdentity();
            id.AddClaim(new Claim("1", "1"));
            id.AddClaim(new Claim("2", "2"));
            var user = new ClaimsPrincipal(id);

            Assert.IsFalse(await authorizationService.AuthorizeAsync(user, "0"));
            Assert.IsTrue(await authorizationService.AuthorizeAsync(user, "1"));
            Assert.IsTrue(await authorizationService.AuthorizeAsync(user, "2"));
            Assert.IsFalse(await authorizationService.AuthorizeAsync(user, "3"));
        }
    }
}
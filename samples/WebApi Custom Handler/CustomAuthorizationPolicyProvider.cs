using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization;

namespace WebApi_Custom_Handler
{
    public class CustomAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        public CustomAuthorizationPolicyProvider(AuthorizationOptions options) : base(options)
        {
        }

        public override Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith("Claim_", StringComparison.InvariantCultureIgnoreCase))
            {
                var builder = new AuthorizationPolicyBuilder();
                var claimName = policyName.Substring(6);
                builder.RequireClaim(claimName, "1", "true");
                var policy = builder.Build();
                return Task.FromResult(policy);
            }
            return base.GetPolicyAsync(policyName);
        }
    }
}
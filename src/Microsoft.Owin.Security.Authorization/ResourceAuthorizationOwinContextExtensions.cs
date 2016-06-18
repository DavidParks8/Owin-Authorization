using System;

namespace Microsoft.Owin.Security.Authorization
{
    public static class ResourceAuthorizationOwinContextExtensions
    {
        public const string Key = "idm:resourceAuthorizationDependencies";

        public static void SetDependencies(this IOwinContext context, AuthorizationDependencies dependencies)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));
            context.Set(Key, dependencies);
        }

        public static AuthorizationDependencies GetDependencies(this IOwinContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));
            return context.Get<AuthorizationDependencies>(Key);
        }
    }
}
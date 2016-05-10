using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Microsoft.Owin.Security.Authorization.Properties
{
    internal static class ResourceHelper
    {
        /// <summary>
        /// The AuthorizationPolicy named: '{0}' was not found.
        /// </summary>
        internal static string FormatException_AuthorizationPolicyNotFound(object p0)
        {
            return string.Format(CultureInfo.CurrentCulture, Resources.Exception_AuthorizationPolicyNotFound, p0);
        }
    }
}
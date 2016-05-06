using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Owin.Security.Authorization
{
    [SuppressMessage("Microsoft.Design", "CA1040:AvoidEmptyInterfaces", Justification = "Serves as a pivot point for inheritance")]
    public interface IResourceAuthorize : IAuthorizeData
    {
        
    }
}

namespace Microsoft.Owin.Security.Authorization
{
    public interface IOwinContextAccessor
    {
        IOwinContext Context { get; }
    }
}

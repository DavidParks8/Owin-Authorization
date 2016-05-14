using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Authorization.Infrastructure
{
    public interface IRequirementHandlerTests
    {
        Task HandleAsyncShouldThrowWhenPassedNullContext();
        Task HandleAsyncShouldSucceed();
        Task HandleAsyncShouldFail();
    }
}

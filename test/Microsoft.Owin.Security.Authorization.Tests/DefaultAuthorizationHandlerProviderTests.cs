using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Microsoft.Owin.Security.Authorization.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DefaultAuthorizationHandlerProviderTests
    {
        [SuppressMessage("Microsoft.Usage", "CA1806:DoNotIgnoreMethodResults", MessageId = "Microsoft.Owin.Security.Authorization.DefaultAuthorizationHandlerProvider", Justification = Justifications.ExpectedException)]
        [TestMethod, UnitTest, ExpectedException(typeof(ArgumentNullException))]
        public void ConstructorShouldThrowWhenHandlersIsNull()
        {
            // ReSharper disable once ObjectCreationAsStatement
            new DefaultAuthorizationHandlerProvider((IAuthorizationHandler[]) null);
        }

        [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = Justifications.MustBeInstanceMethod)]
        [SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate", Justification = Justifications.MustBeInstanceMethod)]
        [TestMethod, UnitTest]
        public async Task GetHandlersAsyncShouldReturnTheCorrectHandlers()
        {
            var handler = new AssertionRequirement(context => true);
            var provider = new DefaultAuthorizationHandlerProvider(handler);
            var handlers = (await provider.GetHandlersAsync()).ToArray();

            Assert.AreEqual(1, handlers.Length);
            Assert.AreSame(handler, handlers[0]);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.Authorization
{
    /// <summary>Attribute for a test category which allows enums instead of strings.</summary>
    /// <remarks>David, 9/7/2014.</remarks>
    /// <seealso cref="T:Microsoft.VisualStudio.TestTools.UnitTesting.TestCategoryBaseAttribute"/>
    [ExcludeFromCodeCoverage]
    public abstract class TestCategoryAttribute : TestCategoryBaseAttribute
    {
        public override IList<string> TestCategories { get; }

        protected TestCategoryAttribute(string category)
        {
            TestCategories = new List<string> { category };
        }
    }

    /// <summary>Attribute for integration test category.</summary>
    /// <seealso cref="T:DUnitTestTools.TestCategoryAttribute"/>
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class IntegrationAttribute : TestCategoryAttribute
    {
        public IntegrationAttribute() : base("Integration") { }
    }

    /// <summary>Attribute for unit test category.</summary>
    /// <seealso cref="T:DUnitTestTools.TestCategoryAttribute"/>
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class UnitTestAttribute : TestCategoryAttribute
    {
        public UnitTestAttribute() : base("Unit") { }
    }

    /// <summary>Attribute for unit test category.</summary>
    /// <seealso cref="T:DUnitTestTools.TestCategoryAttribute"/>
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class SystemTestAttribute : TestCategoryAttribute
    {
        public SystemTestAttribute() : base("System") { }
    }
}

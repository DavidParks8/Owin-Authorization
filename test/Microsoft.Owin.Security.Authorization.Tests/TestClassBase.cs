﻿using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Owin.Security.Authorization
{
    [TestClass, ExcludeFromCodeCoverage]
    public abstract class TestClassBase
    {
        protected MockRepository Repository { get; } = new MockRepository(MockBehavior.Strict);
    }
}

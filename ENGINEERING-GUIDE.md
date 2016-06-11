# Engineering guidelines

*   [Code Reviews and Check-ins](#code-reviews-and-check-ins)
*   [Source Code Management](#source-code-management)
*   [Coding Guidelines](#coding-guidelines)

## Code Reviews and Check-ins

To help ensure that only the highest quality code makes its way into the project, please submit all your code changes to GitHub as PRs. This includes runtime code changes, unit test updates, and updates to samples. For example, sending a PR for just an update to a unit test might seem like a waste of time but the unit tests are just as important as the product code and as such, reviewing changes to them is also just as important.

The advantages are numerous: improving code quality, more visibility on changes and their potential impact, avoiding duplication of effort, and creating general awareness of progress being made in various areas.

## Source Code Management

### Branch Strategy

In general:

*   `master` has the code for the latest release on NuGet.org (e.g. alpha, beta, RC, RTM)
*   `dev` has the code that is being worked on but not yet released. This is the branch into which devs normally submit pull requests and merge changes into.

### Solution and Project Folder Structure and Naming

Solution files go in the repo root.

Solutions need to contain solution folders that match the physical folders (`src`, `test`, etc.).

For example, in the `Fruit` repo with the `Banana` and `Lychee` projects you would have these files checked in:

    /Fruit.sln
    /src
    /src/Microsoft.AspNet.Banana
    /src/Microsoft.AspNet.Banana/project.json
    /src/Microsoft.AspNet.Banana/Banana.kproj
    /src/Microsoft.AspNet.Banana/Banana.cs
    /src/Microsoft.AspNet.Banana/Util/BananaUtil.cs
    /src/Microsoft.AspNet.Lychee
    /src/Microsoft.AspNet.Lychee/project.json
    /src/Microsoft.AspNet.Lychee/Lychee.kproj
    /src/Microsoft.AspNet.Lychee/Lychee.cs
    /src/Microsoft.AspNet.Lychee/Util/LycheeUtil.cs
    /test
    /test/Microsoft.AspNet.Banana.Tests
    /test/Microsoft.AspNet.Banana.Tests/project.json
    /test/Microsoft.AspNet.Banana.Tests/BananaTest.kproj
    /test/Microsoft.AspNet.Banana.Tests/BananaTest.cs
    /test/Microsoft.AspNet.Banana.Tests/Util/BananaUtilTest.cs

### Assembly Naming Pattern

The general naming pattern is `Microsoft.Owin.Security.<area>.<subarea>`.

### Build System

We use [Visual Studio Team Services](https://www.visualstudio.com/en-us/products/visual-studio-team-services-vs.aspx) for builds and releases.

### Samples

Please ensure that all samples go in a `samples/` sub-folder in the repo.

Samples should use nuget packages and not reference the source projects directly.  This is so that samples can be run as standalone projects.

## Coding Guidelines

### Coding Style Guidelines – General

The most general guideline is that we use all the VS default settings in terms of code formatting.

2.  Use `_camelCase` for internal and private fields and use `readonly` where possible. Prefix instance fields with `_`, static fields with `s_` and thread static fields with `t_`. When used on static fields, `readonly` should come after `static` (i.e. `static readonly` not `readonly static`).
3.  Avoid `this.` unless absolutely necessary
4.  Always specify member visiblity, even if it's the default (i.e. `private string _foo;` not `string _foo;`)

### Usage of the Var Keyword

The `var` keyword is to be used as much as the compiler will allow. For example, these are correct:
```cs
var fruit = "Banana";
var fruits = new List<Fruit>();
var flavor = fruit.GetFlavor();
string fruit = null; // can't use "var" because the type isn't known (though you could do (string)null, don't!)
const string expectedName = "name"; // can't use "var" with const
```

The following are incorrect:
```cs
string fruit = "Banana";
List<Fruit> fruits = new List<Fruit>();
FruitFlavor flavor = fruit.GetFlavor();
```

### Use C# Type Keywords in Favor of .NET Type Names

When using a type that has a C# keyword the keyword is used in favor of the .NET type name. For example, these are correct:

```cs
public string TrimString(string s) {
    return string.IsNullOrEmpty(s)
        ? null
        : s.Trim();
}

var intTypeName = nameof(Int32); // can't use C# type keywords with nameof
```

The following are incorrect:

```cs
public String TrimString(String s) {
    return String.IsNullOrEmpty(s)
        ? null
        : s.Trim();
}
```

### Line Breaks

Windows uses `\r\n`, OS X and Linux uses `\n`. When it is important, use `Environment.NewLine` instead of hard-coding the line break.

Note: this may not always be possible or necessary.

Be aware that these line-endings may cause problems in code when using `@""` text blocks with line breaks.

### File Path Separators

Windows uses `\` and OS X and Linux use `/` to separate directories. Instead of hard-coding either type of slash, use [`Path.Combine()`](https://msdn.microsoft.com/en-us/library/system.io.path.combine(v=vs.110).aspx) or [`Path.DirectorySeparatorChar`](https://msdn.microsoft.com/en-us/library/system.io.path.directoryseparatorchar(v=vs.110).aspx).

If this is not possible (such as in scripting), use a forward slash. Windows is more forgiving than Linux in this regard.

### When to Use internals vs. public and When to Use InternalsVisibleTo

As a modern set of frameworks, usage of internal types and members is allowed, but discouraged.

`InternalsVisibleTo` is used only to allow a unit test to test internal types and members of its runtime assembly. We do not use `InternalsVisibleTo` between two runtime assemblies.

If two runtime assemblies need to call each other's APIs, the APIs must be public. If we need it, it is likely that others need it.

### Argument Null Checking

To throw a runtime exception, add an explicit null check and throw an `ArgumentNullException`. Null checking is required for parameters that cannot be null (big surprise!).

### Async Method Patterns

By default all async methods must have the `Async` suffix.

Passing cancellation tokens is done with an optional parameter with a value of `default(CancellationToken)`, which is equivalent to `CancellationToken.None` (one of the few places that we use optional parameters).

Sample async method:

```cs
public Task GetDataAsync(
    QueryParams query,
    int maxData,
    CancellationToken cancellationToken = default(CancellationToken))
{
    ...
}
```
### Use Only Complete Words or Common/Standard Abbreviations in Public APIs

Public namespaces, type names, member names, and parameter names must use complete words or common/standard abbreviations.

These are correct:

```cs
public void AddReference(AssemblyReference reference);
public EcmaScriptObject SomeObject { get; }
```
These are incorrect:

```cs
public void AddRef(AssemblyReference ref);
public EcmaScriptObject SomeObj { get; }
```

### Extension Method Patterns

The general rule is: if a regular method would suffice, avoid extension methods.

Internal extension methods are allowed, but bear in mind the previous guideline: ask yourself if an extension method is truly the most appropriate pattern.

Extension methods are often difficult to mock for external developers, and thus should be avoided for public methods.

The namespace of the extension method class should generally be the namespace that represents the functionality of the extension method, as opposed to the namespace of the target type. One common exception to this is that the namespace for middleware extension methods is normally always the same is the namespace of `IAppBuilder`.

The class name of an extension method container (also known as a "sponsor type") should generally follow the pattern of `<Feature>Extensions`, `<Target><Feature>Extensions`, or `<Feature><Target>Extensions`. For example:

```cs
namespace Food 
{
    class Fruit { ... }
}

namespace Fruit.Eating 
{
    internal class FruitExtensions 
    { 
	    public static void Eat(this Fruit fruit); 
	}
	
  OR
    
    internal class FruitEatingExtensions 
    { 
	    public static void Eat(this Fruit fruit); 
	}
	
  OR

	internal class EatingFruitExtensions 
    { 
	    public static void Eat(this Fruit fruit); 
	}
}
```

When writing extension methods for an interface the sponsor type name must not start with an `I`.

### Doc Comments

The person writing the code will write the doc comments. Public APIs only. No need for doc comments on non-public types.

Note: Public means callable by a customer, so it includes protected APIs. However, some public APIs might still be "for internal use only" but need to be public for technical reasons. We will still have doc comments for these APIs but they will be documented as appropriate.

### Assertions

Use `Debug.Assert()` to assert a condition in the code. Do not use Code Contracts (e.g. `Contract.Assert`).

Please note that assertions are only for our own internal debugging purposes. They do not end up in the released code, so to alert a developer of a condition use an exception.

### Tests

We use the [Visual Studio unit testing framework](https://en.wikipedia.org/wiki/Visual_Studio_Unit_Testing_Framework) for all unit testing.

#### Assembly Naming

The tests for the `Microsoft.Fruit` assembly live in the `Microsoft.Fruit.Tests` assembly.

In general there should be exactly one test assembly for each product runtime assembly.

#### Test Classes and Code Coverage
All test classes should be decorated with `[ExcludeFromCodeCoverage]`. 

#### Unit Test Class Naming

Test class names end with `Tests` and live in the same namespace as the class being tested. For example, the unit tests for the `Microsoft.Fruit.Banana` class would be in a `Microsoft.Fruit.BananaTest` class in the test assembly.

#### Unit Test Method Naming

Unit test method names must be descriptive about _what is being tested_, _under what conditions_, and _what the expectations are_. Pascal casing should be used. The following test name is correct:

    PublicApiArgumentsShouldHaveNotNullAnnotation

The following test names are incorrect:

    Test1
    Constructor
    FormatString
    GetData

#### Unit Test Structure

The contents of every unit test should be split into three distinct stages, optionally separated by these comments:

```cs
// Arrange  
// Act  
// Assert 
```
The crucial thing here is that the `Act` stage is exactly one statement. That one statement is nothing more than a call to the one method that you are trying to test. Keeping that one statement as simple as possible is also very important. For example, this is not ideal:

```cs
int result = myObj.CallSomeMethod(
					GetComplexParam1(), 
					GetComplexParam2(), 
					GetComplexParam3()
				);
```

This style is not recommended because way too many things can go wrong in this one statement. All the `GetComplexParamN()` calls can throw for a variety of reasons unrelated to the test itself. It is thus unclear to someone running into a problem why the failure occurred.

The ideal pattern is to move the complex parameter building into the `Arrange` section:
```cs
// Arrange
P1 p1 = GetComplexParam1();
P2 p2 = GetComplexParam2();
P3 p3 = GetComplexParam3();

// Act
int result = myObj.CallSomeMethod(p1, p2, p3);

// Assert
Assert.AreEqual(1234, result);
```

Now the only reason the line with `CallSomeMethod()` can fail is if the method itself blew up.

#### Use the Most Appropriate Assertion

Please use the most appropriate assertion for your test. This will make the tests a lot more readable and also allow the test runner to report the best possible errors (whether it's local or the CI machine). For example, this is bad:

```cs
Assert.IsTrue("abc123" == someString);
```

This is good:

```cs
Assert.AreEqual("abc123", someString);
```

#### Parallel Tests

By default all unit test assemblies should run in parallel mode, which is the default. Unit tests shouldn't depend on any shared state, and so should generally be runnable in parallel. If the tests fail in parallel, the first thing to do is to figure out _why_; do not just disable parallel tests!

using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Moq;
using System.Linq;
using Xunit;

namespace QuokkaDev.Saas.Authentication.Tests;

public class IApplicationBuilderExtensionsUnitTest
{
    [Fact(DisplayName = "UseMultiTenantAuthentication should register middleware")]
    public void UseMultiTenantAuthentication_Should_Register_Middleware()
    {
        // Arrange
        var mock = new Mock<IApplicationBuilder>();

        // Act
#pragma warning disable RCS1196 // Call extension method as instance method.
        IApplicationBuilderExtensions.UseMultiTenantAuthentication(mock.Object);
#pragma warning restore RCS1196 // Call extension method as instance method.

        // Assert
        mock.Invocations.Single(invocation => invocation.Method.Name.StartsWith("Use"))
           .Should().NotBeNull();
    }
}
using FluentAssertions;
using HttpContextMoq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Moq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace QuokkaDev.Saas.Authentication.Tests
{
    public class TenantAuthMiddlewareUnitTest
    {
        public TenantAuthMiddlewareUnitTest()
        {
        }

        [Fact(DisplayName = "Null next delegate should throw exception")]
        public void Null_Next_Delegate_Should_Throw_Exception()
        {
            var middlewareConstruction = () => new TenantAuthMiddleware(null!);
            middlewareConstruction.Should().Throw<ArgumentNullException>();
        }

        [Fact(DisplayName = "If handlers are registered then should be used")]
        public async Task If_Handlers_Are_Registered_Then_Should_Be_Used()
        {
            // Arrange
            var delegateMock = new Mock<RequestDelegate>();
            TenantAuthMiddleware middleware = new(delegateMock.Object);
            var httpContextMock = new HttpContextMock();

            var handlerMockFailure = new Mock<IAuthenticationRequestHandler>();
            handlerMockFailure.Setup(m => m.HandleRequestAsync()).ReturnsAsync(false);

            var handlerMockSuccess = new Mock<IAuthenticationRequestHandler>();
            handlerMockSuccess.Setup(m => m.HandleRequestAsync()).ReturnsAsync(true);

            List<AuthenticationScheme> schemas = new()
            {
                new AuthenticationScheme("myHandlerFail", "myHandlerFail", typeof(IAuthenticationHandler)),
                new AuthenticationScheme("myHandler", "myHandler", typeof(IAuthenticationHandler))
            };

            var schemeProviderMock = new Mock<IAuthenticationSchemeProvider>();
            schemeProviderMock.Setup(m => m.GetRequestHandlerSchemesAsync()).ReturnsAsync(schemas);

            var authenticationHandlerProviderMock = new Mock<IAuthenticationHandlerProvider>();
            authenticationHandlerProviderMock.Setup(m => m.GetHandlerAsync(httpContextMock, "myHandlerFail")).ReturnsAsync(handlerMockFailure.Object);
            authenticationHandlerProviderMock.Setup(m => m.GetHandlerAsync(httpContextMock, "myHandler")).ReturnsAsync(handlerMockSuccess.Object);

            httpContextMock.RequestServicesMock.Mock.Setup(m => m.GetService(typeof(IAuthenticationHandlerProvider))).Returns(authenticationHandlerProviderMock.Object);

            // Act
            await middleware.Invoke(httpContextMock, schemeProviderMock.Object);

            // Assert            
            authenticationHandlerProviderMock.Verify(m => m.GetHandlerAsync(It.IsAny<HttpContext>(), It.IsAny<string>()), Times.Exactly(2));
            handlerMockFailure.Verify(m => m.HandleRequestAsync(), Times.Once);
            handlerMockSuccess.Verify(m => m.HandleRequestAsync(), Times.Once);
        }

        [Fact(DisplayName = "Middleware authenticate user")]
        public async Task Middleware_Authenticate_User()
        {
            // Arrange

            ClaimsPrincipal principal = new(new List<ClaimsIdentity>() {
                new ClaimsIdentity(new List<Claim>(){
                    new Claim("Username", "Admin")
                })}
            );
            var authenticateResult = AuthenticateResult.Success(new AuthenticationTicket(principal, "myHandler"));

            var authenticationServiceMock = new Mock<IAuthenticationService>();
            authenticationServiceMock.Setup(m => m.AuthenticateAsync(It.IsAny<HttpContext>(), "myHandler")).ReturnsAsync(authenticateResult);

            var delegateMock = new Mock<RequestDelegate>();
            TenantAuthMiddleware middleware = new(delegateMock.Object);
            var httpContextMock = new HttpContextMock();

            List<AuthenticationScheme> schemas = new();

            var defaultScheme = new AuthenticationScheme("myHandler", "myHandler", typeof(IAuthenticationHandler));

            var schemeProviderMock = new Mock<IAuthenticationSchemeProvider>();
            schemeProviderMock.Setup(m => m.GetRequestHandlerSchemesAsync()).ReturnsAsync(schemas);
            schemeProviderMock.Setup(m => m.GetDefaultAuthenticateSchemeAsync()).ReturnsAsync(defaultScheme);

            var authenticationHandlerProviderMock = new Mock<IAuthenticationHandlerProvider>();

            httpContextMock.RequestServicesMock.Mock.Setup(m => m.GetService(typeof(IAuthenticationHandlerProvider))).Returns(authenticationHandlerProviderMock.Object);
            httpContextMock.RequestServicesMock.Mock.Setup(m => m.GetService(typeof(IAuthenticationService))).Returns(authenticationServiceMock.Object);

            // Act
            await middleware.Invoke(httpContextMock, schemeProviderMock.Object);

            // Assert            
            authenticationHandlerProviderMock.Verify(m => m.GetHandlerAsync(It.IsAny<HttpContext>(), It.IsAny<string>()), Times.Never);
            httpContextMock.User.Should().NotBeNull();
            httpContextMock.User.Should().BeSameAs(principal);
        }

        [Fact(DisplayName = "Middleware does not authenticate user")]
        public async Task Middleware_Does_Not_Authenticate_User()
        {
            // Arrange           

            var authenticationServiceMock = new Mock<IAuthenticationService>();
            authenticationServiceMock.Setup(m => m.AuthenticateAsync(It.IsAny<HttpContext>(), "myHandler")).ReturnsAsync((AuthenticateResult)null!);

            var delegateMock = new Mock<RequestDelegate>();
            TenantAuthMiddleware middleware = new(delegateMock.Object);
            var httpContextMock = new HttpContextMock();

            List<AuthenticationScheme> schemas = new();

            var defaultScheme = new AuthenticationScheme("myHandler", "myHandler", typeof(IAuthenticationHandler));

            var schemeProviderMock = new Mock<IAuthenticationSchemeProvider>();
            schemeProviderMock.Setup(m => m.GetRequestHandlerSchemesAsync()).ReturnsAsync(schemas);
            schemeProviderMock.Setup(m => m.GetDefaultAuthenticateSchemeAsync()).ReturnsAsync(defaultScheme);

            var authenticationHandlerProviderMock = new Mock<IAuthenticationHandlerProvider>();

            httpContextMock.RequestServicesMock.Mock.Setup(m => m.GetService(typeof(IAuthenticationHandlerProvider))).Returns(authenticationHandlerProviderMock.Object);
            httpContextMock.RequestServicesMock.Mock.Setup(m => m.GetService(typeof(IAuthenticationService))).Returns(authenticationServiceMock.Object);

            // Act
            await middleware.Invoke(httpContextMock, schemeProviderMock.Object);

            // Assert            
            authenticationHandlerProviderMock.Verify(m => m.GetHandlerAsync(It.IsAny<HttpContext>(), It.IsAny<string>()), Times.Never);
            httpContextMock.User.Identities.Should().BeEmpty();
        }
    }
}

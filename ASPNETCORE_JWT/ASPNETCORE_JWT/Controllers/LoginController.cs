using ASPNETCORE_JWT.Extentions;
using ASPNETCORE_JWT.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;

namespace ASPNETCORE_JWT.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class LoginController : ControllerBase
    {
        private IHttpContextAccessor _httpContextAccessor { get; }
        private JwtService _jwtService { get; }
        public LoginController(IHttpContextAccessor httpContextAccessor, JwtService jwtService)
        {
            _httpContextAccessor = httpContextAccessor;
            _jwtService = jwtService;
        }

        [HttpPost]
        public string Login()
        {
            var userId = Guid.NewGuid();
            var jwt = _jwtService.GenerateJwt(userId);
            return jwt;
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public Guid GetUserId()
        {
            return _httpContextAccessor.GetUserId();
        }
    }
}

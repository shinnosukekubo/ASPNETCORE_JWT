using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Security.Claims;

namespace ASPNETCORE_JWT.Extentions
{
    public static class HttpContextAccessorExtension
    {
        public static Guid GetUserId(this IHttpContextAccessor self)
        {
            var nameIdentifier = self.HttpContext.User?.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            if (nameIdentifier == null)
                throw new Exception("ClaimにIdが含まれていません");
            
            return Guid.Parse(nameIdentifier.Value);
        }
    }
}

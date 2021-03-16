using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;


namespace ASPNETCORE_JWT.Services
{

    public class JwtService
    {
        private RsaSecurityKey _rsa { get; }
        private IConfiguration _configuration { get; }
        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
            // 公開鍵の設定
            RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(
                source: Convert.FromBase64String(configuration["Jwt:Asymmetric:PublicKey"]),
                bytesRead: out int _
            );
            _rsa = new RsaSecurityKey(rsa);
        }

        public string GenerateJwt(Guid userId)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(
                source: Convert.FromBase64String(_configuration["Jwt:Asymmetric:PrivateKey"]),
                bytesRead: out int _);

            var signingCredentials = new SigningCredentials(
                key: new RsaSecurityKey(rsa)
                {
                    // using文でも破棄されないキャッシュがあり
                    // 偶数リクエストで失敗するため、修正されるまで追加
                    CryptoProviderFactory = new CryptoProviderFactory()
                    {
                        CacheSignatureProviders = false
                    }
                },
                algorithm: SecurityAlgorithms.RsaSha256
            );

            var tokenExpiredHours = double.Parse(_configuration["Jwt:TokenExpiredHours"]);

            // JWTのペイロードの中身
            var jwtToken = new JwtSecurityToken(
                audience: "JWT_Client",
                issuer: "JWT_Server",
                claims: new Claim[] {
                    new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                    new Claim(ClaimTypes.Version, "1.0.0.0")
                },
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddHours(tokenExpiredHours),
                signingCredentials: signingCredentials
            );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            return token;
        }

        public TokenValidationParameters GetTokenValidationParameters()
        {
            // 公開鍵でトークンの検証
            // JWTの有効期限の検証
            return new TokenValidationParameters
            {
                IssuerSigningKey = _rsa,
                RequireSignedTokens = false,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                LifetimeValidator = LifetimeValidator,
                ValidateAudience = false,
                ValidateIssuer = false,
                CryptoProviderFactory = new CryptoProviderFactory()
                {
                    // using文でも破棄されないキャッシュがあり
                    // 偶数リクエストで失敗するため、修正されるまで追加
                    CacheSignatureProviders = false
                }
            };
        }


        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken token, TokenValidationParameters @params)
        {
            if (expires != null)
            {
                return expires > DateTime.UtcNow;
            }
            return false;
        }
    }
}

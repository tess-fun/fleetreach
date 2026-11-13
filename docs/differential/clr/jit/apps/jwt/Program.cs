using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
static class Program
{
    static void Main()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('k', 64)));
        var h = new JwtSecurityTokenHandler();
        var token = h.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "ann"), new Claim("role", "admin") }),
            Issuer = "iss", Audience = "aud", Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        });
        var text = h.WriteToken(token);
        var p = h.ValidateToken(text, new TokenValidationParameters { ValidIssuer = "iss", ValidAudience = "aud", IssuerSigningKey = key }, out var validated);
        var jw = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var t2 = jw.CreateToken("{\"sub\":\"x\"}", new SigningCredentials(key, SecurityAlgorithms.HmacSha512));
        var r = jw.ValidateToken(t2, new TokenValidationParameters { ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false, IssuerSigningKey = key });
        try { h.ValidateToken(text + "x", new TokenValidationParameters { IssuerSigningKey = key }, out _); } catch (Exception e) { Console.WriteLine(e.GetType().Name); }
        Console.WriteLine($"{p.Identity.Name} {validated.ValidTo:yyyy} {r.IsValid}");
    }
}

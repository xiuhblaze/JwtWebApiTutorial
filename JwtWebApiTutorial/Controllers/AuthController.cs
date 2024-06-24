using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtWebApiTutorial.DTOs;
using JwtWebApiTutorial.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtWebApiTutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        public static User user = new User();
        public readonly IConfiguration _configuration;

        // CONSTRUCTOR

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // ENDPOINTS

        [HttpGet("getme"), Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = User?.Identity?.Name ?? string.Empty;
            var userName2 = User.FindFirstValue(ClaimTypes.Name);            
            var role = User.FindFirstValue(ClaimTypes.Role);

            //var idxClaim = User?.Claims.FirstOrDefault(claim => claim.Type.Equals("idx", StringComparison.OrdinalIgnoreCase))?.Value;
            var idxClaim = User?.Claims.First(claim => claim.Type == "idx").Value;
            
            return Ok(new {
                userName,
                userName2,
                role,
                idxClaim });
        } // GetMe

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        } // Register

        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        // PRIVATE

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("idx", Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        } // CreateToken

        private void CreatePasswordHash(string password, out byte[] passordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        } // CreatePasswordHash

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                return computedHash.SequenceEqual(passwordHash);
            }
        } // VerifyPasswordHash
    }
}


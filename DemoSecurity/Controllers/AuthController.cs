using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DemoSecurity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        /// <summary>
        /// Generate Token Authentication - JWT
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> Token(Credentials credentials) 
        {

            if (!IsAdmin(credentials) && !IsUser(credentials))
            {
                return Unauthorized();
            }

            var secretKey = "MyAnonymousSecuredSecretKey";
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var jwt = new JwtSecurityToken
            (
                claims: BuildClaims(credentials),
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512)
            );

            var token = new JwtSecurityTokenHandler().WriteToken(jwt);

            return Ok(token);
        }



        /// <summary>
        /// Type User Or Admin
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        private IEnumerable<Claim> BuildClaims(Credentials credentials)
        {
            return new[]
            {
                new Claim("userType", IsAdmin(credentials) ? "admin" : "user")
            };
        }


        /// <summary>
        /// Method If Is User
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        private static bool IsUser(Credentials credentials)
        {
            return credentials.Username == "user" && credentials.Password == "user";
        }


        /// <summary>
        /// Method If Administrator
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        private static bool IsAdmin(Credentials credentials)
        {
            return credentials.Username == "admin" && credentials.Password == "admin";

        }
    }



    /// <summary>
    /// Class Credentials
    /// </summary>
    public class Credentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}

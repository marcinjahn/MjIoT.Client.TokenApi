using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using MJIoT_EFCoreModel;

namespace MJIoT_TokenIssuer.Controllers
{
    [Produces("application/json")]
    [Route("api/Token")]
    public class TokenController : Controller
    {
        [AllowAnonymous]
        [HttpPost]
        public IActionResult RequestToken([FromBody] TokenRequest request)
        {
            var userId = GetUserId(request);

            if (userId.HasValue)
            {
                var claims = new[]
                {
                    //new Claim(ClaimTypes.Name, request.Username),
                    new Claim("iss", "MJIoT Authentication Service"),
                    new Claim("sub", userId.Value.ToString()),
                    new Claim("exp", DateTimeOffset.UtcNow.AddMonths(6).ToUnixTimeSeconds().ToString()),
                };

                //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GetPrivateKey()));
                //var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

                //var token = new JwtSecurityToken(
                //    issuer: "yourdomain.com",
                //    audience: "yourdomain.com",
                //    claims: claims,
                //    expires: DateTime.Now.AddMinutes(30),
                //    signingCredentials: creds);

                var manager = new TokenManager();
                var token = manager.CreateToken(claims);

                return Ok(token);
            }

            return Unauthorized();
        }



        private int? GetUserId(TokenRequest request)
        {
            MJIoT_EFCoreModel.Models.Users userCheck;
            using (var context = new MJIoTDbContext())
            {
                userCheck = context.Users
                    .Where(n => n.Login == request.Username && n.Password == request.Password)
                    .FirstOrDefault();
            }

            if (userCheck != null)
                return userCheck.Id;
            else
                return null;
        }


        //// GET: api/Token
        //[HttpGet]
        //public IEnumerable<string> Get()
        //{
        //    return new string[] { "value1", "value2" };
        //}

        //// GET: api/Token/5
        //[HttpGet("{id}", Name = "Get")]
        //public string Get(int id)
        //{
        //    return "value";
        //}
        
        //// POST: api/Token
        ////[HttpPost]
        ////public void Post([FromBody]string value)
        ////{
        ////}
        
        //// PUT: api/Token/5
        //[HttpPut("{id}")]
        //public void Put(int id, [FromBody]string value)
        //{
        //}
        
        //// DELETE: api/ApiWithActions/5
        //[HttpDelete("{id}")]
        //public void Delete(int id)
        //{
        //}
    }
}

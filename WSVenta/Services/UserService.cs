using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WSVenta.Models.Request;
using WSVenta.Models.Response;
using WSVenta.Models;
using WSVenta.Tools;
using WSVenta.Models.Common;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace WSVenta.Services
{
    public class UserService : IUserService
    {
        private readonly AppSettings _appSettings;

        public UserService(IOptions<AppSettings> appsettings)
        {
            _appSettings = appsettings.Value;
        }

        public UserResponse Auth(AuthRequest model)
        {
            UserResponse userRes = new UserResponse();
            using(var db = new VentaRealContext())
            {
                string spasword = Encrypt.GetSHA256(model.Password);
                var usuario = db.Usuario.Where(d => d.Email == model.Emal && d.Password == spasword).FirstOrDefault();

                if (usuario == null) return null;

                userRes.Email = usuario.Email;
                userRes.Token = GetToken(usuario);

            }
            return userRes;
        }

        private string GetToken(Usuario usuario)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var llave = Encoding.ASCII.GetBytes(_appSettings.Secreto);
            var tokenDescripto = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                    new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                        new Claim(ClaimTypes.Email, usuario.Email)
                    }
                    ),
                Expires  = DateTime.UtcNow.AddDays(60),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(llave),SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescripto);
            return tokenHandler.WriteToken(token);
        }
    }
}

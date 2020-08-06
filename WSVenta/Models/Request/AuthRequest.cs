using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WSVenta.Models.Request
{
    public class AuthRequest
    {
        [Required]
        public string Emal { get; set; }
        [Required]
        public string Password { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OktaAuthorizationForMobile.Models
{
    public class SecureViewModel
    {
        public SecureViewModel()
        {
            IdTokenClaims = new List<string>();
        }

        public List<string> IdTokenClaims { get; set; }
    }
}

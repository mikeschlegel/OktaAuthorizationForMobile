using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OktaSecuredApi.Controllers
{
    [Authorize]
    [Route("secure")]
    public class SecureController : Controller
    {
        [HttpGet]
        public IActionResult Get()
        {
            var user = User;
            var testMessage = new TestMessage { Message = "Hello from the secure API." };
            return Json(testMessage);
        }
    }

    public class TestMessage
    {
        public string Message { get; set; }
    }
}

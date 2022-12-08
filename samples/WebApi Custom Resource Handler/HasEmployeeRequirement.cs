using Microsoft.Owin.Security.Authorization;
using System;
using System.Collections.Generic;
using System.Web;
using WebApi_Custom_Resource_Handler.Controllers;

namespace WebApi_Custom_Resource_Handler
{
    public class HasEmployeeNumberRequirement : IAuthorizationRequirement
    {
        public HasEmployeeNumberRequirement()
        {
        }
    }
}
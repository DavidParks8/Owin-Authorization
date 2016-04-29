using Microsoft.Owin;
using Microsoft.Owin.Security.Authorization.Infrastructure;
using Owin;

[assembly: OwinStartup(typeof(MVC_OWIN.Startup))]

namespace MVC_OWIN
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseAuthorization(options =>
            {
                options.AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"));
                options.AddPolicy("EmployeeNumber6", policy => policy.RequireClaim("EmployeeNumber", "6"));
            });
        }
    }
}

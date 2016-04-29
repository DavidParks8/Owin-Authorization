using System.Web.Mvc;

namespace MVC_OWIN.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}
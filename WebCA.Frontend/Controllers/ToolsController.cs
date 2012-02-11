using System.Web;
using System.Web.Mvc;

namespace WebCA.Frontend.Controllers
{
    public class ToolsController : Controller
    {
        public ActionResult FileInspector()
        {
            return View();
        }

        [HttpPost]
        public ActionResult FileInspector(HttpPostedFileBase file)
        {
            byte[] data = new byte[file.ContentLength];
            file.InputStream.Read(data, 0, data.Length);

            return View(FileFormatsHelper.ReadPem(data));
        }
    }
}
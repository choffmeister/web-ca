using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Web.Mvc;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using WebCA.Frontend.Extensions;
using WebCA.Frontend.Forms;

namespace WebCA.Frontend.Controllers
{
    public class CertificatesController : Controller
    {
        public ActionResult Index()
        {
            string[] certificates = System.IO.File.ReadAllLines(Path.Combine(this.Server.MapPath("~/App_Data"), "serials.txt"));

            return View(certificates);
        }

        public ActionResult CreateRoot()
        {
            CreateRootCAForm model = new CreateRootCAForm();
            model.NotBefore = DateTime.Today;
            model.NotAfter = DateTime.Today.AddYears(10);

            return View(model);
        }

        [HttpPost]
        public ActionResult CreateRoot(CreateRootCAForm model)
        {
            if (ModelState.IsValid)
            {
                RSACryptoServiceProvider caKey = new RSACryptoServiceProvider(1024);
                X509Certificate caCert = X509Extensions.CreateRootCA(model.CommonName, model.NotBefore, model.NotAfter, caKey);
                PKCS8.PrivateKeyInfo caPrivateKey = PKCS8Extensions.CreateFromRSA(caKey);
                PKCS8.EncryptedPrivateKeyInfo caPrivateKeyEnc = caPrivateKey.Encrypt(model.PrivateKeyPassphrase);

                System.IO.File.WriteAllBytes(Path.Combine(this.Server.MapPath("~/App_Data"), "certs/" + model.CommonName + ".crt"), caCert.RawData);
                System.IO.File.WriteAllText(Path.Combine(this.Server.MapPath("~/App_Data"), "keys/" + model.CommonName + ".key"), "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + string.Join("\n", Split(Convert.ToBase64String(caPrivateKeyEnc.GetBytes()), 64)) + "\n-----END ENCRYPTED PRIVATE KEY-----");
                System.IO.File.AppendAllText(Path.Combine(this.Server.MapPath("~/App_Data"), "serials.txt"), string.Format("{0} {1} {2}\n", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), X509Extensions.FormatSerialNumber(caCert.SerialNumber), caCert.SubjectName));

                return RedirectToAction("Index", "Certificates");
            }
            else
            {
                return View(model);
            }
        }

        public static IEnumerable<string> Split(string str, int chunkSize)
        {
            for (int i = 0; i < str.Length; i += chunkSize)
            {
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
            }
        }
    }
}
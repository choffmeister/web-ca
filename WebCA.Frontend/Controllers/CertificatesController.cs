using System;
using System.IO;
using System.Security.Cryptography;
using System.Web.Mvc;
using Mono.Security;
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
            return View(CertificateKeyManager.ListCertificates());
        }

        public ActionResult Details(string id)
        {
            return View(new ASN1(CertificateKeyManager.GetCertificate(id).RawData));
        }

        public ActionResult Create()
        {
            CreateCertificateForm model = new CreateCertificateForm();
            model.NotBefore = DateTime.Today;
            model.NotAfter = DateTime.Today.AddYears(10);

            return View(model);
        }

        [HttpPost]
        public ActionResult Create(CreateCertificateForm model)
        {
            if (ModelState.IsValid)
            {
                string name = X509Extensions.BuildDistinguishedName(model.Country, model.State, model.Locality, model.Organization, model.OrganizationalUnit, model.CommonName);

                RSACryptoServiceProvider caKey = new RSACryptoServiceProvider(1024);
                X509Certificate caCert = X509Extensions.CreateCertificate(name, model.IsCertificateAuthority, model.NotBefore, model.NotAfter, caKey);
                PKCS8.PrivateKeyInfo caPrivateKey = PKCS8Extensions.CreateFromRSA(caKey);
                PKCS8.EncryptedPrivateKeyInfo caPrivateKeyEnc = caPrivateKey.Encrypt(model.PrivateKeyPassphrase);

                string certificatePath = Path.Combine(this.Server.MapPath("~/App_Data"), "certs\\" + model.CommonName + ".crt.pem");
                string keyPath = Path.Combine(this.Server.MapPath("~/App_Data"), "keys\\" + model.CommonName + ".key.pem");

                CertificateKeyManager.SaveCertificate(caCert, certificatePath);
                CertificateKeyManager.SaveEncryptedPrivateKey(caPrivateKeyEnc, keyPath);
                CertificateKeyManager.AddCertificate(caCert, certificatePath, keyPath);

                return RedirectToAction("Index", "Certificates");
            }
            else
            {
                return View(model);
            }
        }
    }
}
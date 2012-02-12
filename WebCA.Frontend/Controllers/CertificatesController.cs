using System;
using System.IO;
using System.Security.Cryptography;
using System.Web.Mvc;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using WebCA.Frontend.Forms;
using WebCA.Security.Extensions;

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
            X509Certificate certificate = CertificateKeyManager.GetCertificate(id);

            return View(Tuple.Create(id, certificate));
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

                string certificatePath = Path.Combine(this.Server.MapPath("~/App_Data"), "certs\\" + model.CommonName + ".crt.pem").ToLower();
                string keyPath = Path.Combine(this.Server.MapPath("~/App_Data"), "keys\\" + model.CommonName + ".key.pem").ToLower();

                if (System.IO.File.Exists(certificatePath) || System.IO.File.Exists(keyPath))
                {
                    throw new Exception();
                }

                CertificateKeyManager.SaveCertificate(caCert, certificatePath);
                CertificateKeyManager.SaveEncryptedPrivateKey(caPrivateKeyEnc, keyPath);
                CertificateKeyManager.AddCertificate(caCert, certificatePath, keyPath);

                return RedirectToAction("Index");
            }
            else
            {
                return View(model);
            }
        }

        public ActionResult Sign()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Sign(SignCertificateForm model)
        {
            if (ModelState.IsValid)
            {
                X509Certificate subjectCertificate = CertificateKeyManager.GetCertificate(model.SubjectSerial);
                X509Certificate issuerCertificate = CertificateKeyManager.GetCertificate(model.IssuerSerial);
                PKCS8.EncryptedPrivateKeyInfo issuerPrivateKeyEnc = CertificateKeyManager.GetEncryptedPrivateKey(model.IssuerSerial);
                PKCS8.PrivateKeyInfo issuerPrivateKey = issuerPrivateKeyEnc.Decrypt(model.IssuerPrivateKeyPassword);

                X509Certificate signedSubjectCertificate = subjectCertificate.CreateSignedCertificate(issuerCertificate, issuerPrivateKey);
                CertificateKeyManager.SaveCertificate(signedSubjectCertificate, CertificateKeyManager.GetCertificatePath(model.SubjectSerial));

                return RedirectToAction("Index");
            }
            else
            {
                return View(model);
            }
        }

        public ActionResult Download(string format, string serial, string privateKeyPassword)
        {
            X509Certificate certificate;
            PKCS8.EncryptedPrivateKeyInfo privateKeyEnc;

            switch (format)
            {
                case "crt":
                    certificate = CertificateKeyManager.GetCertificate(serial);

                    return new FileContentResult(certificate.RawData, "application/pkix-cert") { FileDownloadName = "key" + "." + format };
                case "crt.pem":
                    certificate = CertificateKeyManager.GetCertificate(serial);

                    return new FileContentResult(PEMContainer.Save(PEMContainer.Certificate, certificate.RawData), "application/x-pem-file") { FileDownloadName = "key" + "." + format };
                case "key":
                    privateKeyEnc = CertificateKeyManager.GetEncryptedPrivateKey(serial);

                    return new FileContentResult(privateKeyEnc.GetBytes(), "application/pkcs8") { FileDownloadName = "key" + "." + format };
                case "key.pem":
                    privateKeyEnc = CertificateKeyManager.GetEncryptedPrivateKey(serial);

                    return new FileContentResult(PEMContainer.Save(PEMContainer.EncryptedPrivateKey, privateKeyEnc.GetBytes()), "application/pkcs8") { FileDownloadName = "key" + "." + format };
                case "pfx":
                    certificate = CertificateKeyManager.GetCertificate(serial);
                    privateKeyEnc = CertificateKeyManager.GetEncryptedPrivateKey(serial);

                    PKCS12 pkcs12 = new PKCS12();
                    RSA key = PKCS8.PrivateKeyInfo.DecodeRSA(privateKeyEnc.Decrypt(privateKeyPassword).PrivateKey);
                    pkcs12.AddCertificate(certificate);
                    pkcs12.AddKeyBag(key);
                    pkcs12.Password = privateKeyPassword;

                    return new FileContentResult(pkcs12.GetBytes(), "application/x-pkcs12") { FileDownloadName = "key" + "." + format };
                default:
                    throw new NotSupportedException(string.Format("Format '{0}' is not supported", format));
            }
        }
    }
}
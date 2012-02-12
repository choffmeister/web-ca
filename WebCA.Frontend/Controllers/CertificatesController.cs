using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Mvc;
using ICSharpCode.SharpZipLib.Core;
using ICSharpCode.SharpZipLib.Zip;
using Mono.Security;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using WebCA.Frontend.Forms;
using WebCA.Security;
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

            this.ViewBag.Serial = id;
            this.ViewBag.SubjectCommonName = certificate.GetSubjectName().GetCommonName();
            this.ViewBag.ASN1TextTree = new ASN1(certificate.RawData).ConvertToStringTree().ToString();

            return View(certificate);
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

                string certificatePath = Path.Combine(CertificateKeyManager.BasePath, "certs\\" + model.CommonName + ".crt.pem").ToLower();
                string keyPath = Path.Combine(CertificateKeyManager.BasePath, "keys\\" + model.CommonName + ".key.pem").ToLower();

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
            var certs = CertificateKeyManager.ListCertificates();

            this.ViewBag.CACerts = certs.Where(n => n.GetIsCertificateAuthority());
            this.ViewBag.Certs = certs;

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

        public ActionResult Download(string id)
        {
            X509Certificate certificate = CertificateKeyManager.GetCertificate(id);

            this.ViewBag.Serial = id;
            this.ViewBag.NewRandomPassword = BitConverter.ToString(SHA1.Create().ComputeHash(Guid.NewGuid().ToByteArray())).Replace("-", "").ToLower().Substring(0, 16);

            return View(certificate);
        }

        [HttpPost]
        public ActionResult Download(string[] format, string serial, string encryptionPassword, string newEncryptionPassword)
        {
            format = format ?? new string[0];

            X509Certificate certificate = CertificateKeyManager.GetCertificate(serial);
            string subjectCommonName = certificate.GetSubjectName().GetCommonName().Replace(" ", "_");
            PKCS8.EncryptedPrivateKeyInfo privateKeyEnc = format.Contains("key") || format.Contains("key-pem") || format.Contains("pfx") ? CertificateKeyManager.GetEncryptedPrivateKey(serial) : null;
            PKCS8.PrivateKeyInfo privateKeyDec = privateKeyEnc != null ? privateKeyEnc.Decrypt(encryptionPassword) : null;
            bool reencrypt = !string.IsNullOrEmpty(newEncryptionPassword);
            Mono.Security.ASN1 a = certificate.GetSubjectName();

            MemoryStream memStream = new MemoryStream();
            ZipOutputStream zipStream = new ZipOutputStream(memStream);
            zipStream.SetLevel(3);

            if (format.Contains("crt"))
            {
                ZipEntry zipEntry = new ZipEntry(subjectCommonName + ".crt");
                zipEntry.DateTime = DateTime.Now;
                zipStream.PutNextEntry(zipEntry);

                StreamUtils.Copy(new MemoryStream(certificate.RawData), zipStream, new byte[4096]);
                zipStream.CloseEntry();
            }

            if (format.Contains("crt-pem"))
            {
                ZipEntry zipEntry = new ZipEntry(subjectCommonName + ".crt.pem");
                zipEntry.DateTime = DateTime.Now;
                zipStream.PutNextEntry(zipEntry);

                StreamUtils.Copy(new MemoryStream(PEMContainer.Save(PEMContainer.Certificate, certificate.RawData)), zipStream, new byte[4096]);
                zipStream.CloseEntry();
            }

            if (format.Contains("key"))
            {
                byte[] key = reencrypt ? privateKeyDec.Encrypt(newEncryptionPassword).GetBytes() : privateKeyDec.GetBytes();

                ZipEntry zipEntry = new ZipEntry(subjectCommonName + ".key");
                zipEntry.DateTime = DateTime.Now;
                zipStream.PutNextEntry(zipEntry);

                StreamUtils.Copy(new MemoryStream(key), zipStream, new byte[4096]);
                zipStream.CloseEntry();
            }

            if (format.Contains("key-pem"))
            {
                byte[] key = reencrypt ? privateKeyDec.Encrypt(newEncryptionPassword).GetBytes() : privateKeyDec.GetBytes();

                ZipEntry zipEntry = new ZipEntry(subjectCommonName + ".key.pem");
                zipEntry.DateTime = DateTime.Now;
                zipStream.PutNextEntry(zipEntry);

                StreamUtils.Copy(new MemoryStream(PEMContainer.Save(reencrypt ? PEMContainer.EncryptedPrivateKey : PEMContainer.PrivateKey, key)), zipStream, new byte[4096]);
                zipStream.CloseEntry();
            }

            if (format.Contains("pfx"))
            {
                PKCS12 pkcs12 = new PKCS12();
                RSA key = PKCS8.PrivateKeyInfo.DecodeRSA(privateKeyDec.PrivateKey);
                pkcs12.AddCertificate(certificate);
                pkcs12.AddKeyBag(key);
                pkcs12.Password = newEncryptionPassword;

                ZipEntry zipEntry = new ZipEntry(subjectCommonName + ".pfx");
                zipEntry.DateTime = DateTime.Now;
                zipStream.PutNextEntry(zipEntry);

                StreamUtils.Copy(new MemoryStream(pkcs12.GetBytes()), zipStream, new byte[4096]);
                zipStream.CloseEntry();
            }

            zipStream.IsStreamOwner = false;
            zipStream.Close();

            memStream.Position = 0;

            return new FileStreamResult(memStream, "application/zip") { FileDownloadName = subjectCommonName + ".zip" };
        }
    }
}
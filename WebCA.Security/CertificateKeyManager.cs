using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;
using WebCA.Security.Extensions;

namespace WebCA.Security
{
    public static class CertificateKeyManager
    {
        public static string SerialsPath
        {
            get { return Path.Combine(BasePath, "serials.txt"); }
        }

        public static string BasePath { get; set; }

        public static void AddCertificate(X509Certificate certificate)
        {
            File.AppendAllText(SerialsPath, string.Format(@"{0} ""{1}"" {2:yyyy-MM-ddTHH:mm:ssZ} {3:yyyy-MM-ddTHH:mm:ssZ}" + "\n",
                X509Extensions.FormatSerialNumber(certificate.SerialNumber),
                certificate.SubjectName,
                certificate.ValidFrom.ToUniversalTime(),
                certificate.ValidUntil.ToUniversalTime()
            ));
        }

        public static string GetCertificatePath(byte[] serial)
        {
            return Path.Combine(BasePath, "certs\\" + serial.FormatSerialNumber(true) + ".crt.pem");
        }

        public static string GetPrivateKeyPath(byte[] serial)
        {
            return Path.Combine(BasePath, "keys\\" + serial.FormatSerialNumber(true) + ".key.pem");
        }

        public static IEnumerable<X509Certificate> ListCertificates()
        {
            return ListCertificateSerials().Select(n => LoadCertificate(n));
        }

        public static IEnumerable<byte[]> ListCertificateSerials()
        {
            string[] lines = File.ReadAllLines(SerialsPath);

            Regex regex = new Regex(@"^(?<SerialNumber>[^\s]+)\s+""(?<SubjectName>.+)""\s+(?<NotBefore>[^\s]+)\s+(?<NotAfter>[^\s]+)\s*$");

            return lines.Select(n =>
            {
                Match match = regex.Match(n);

                if (!match.Success)
                    return null;

                return match.Groups["SerialNumber"].Value.ParseSerialNumber();
            }).Where(n => n != null);
        }

        public static void SaveCertificate(X509Certificate certificate)
        {
            using (FileStream file = new FileStream(GetCertificatePath(certificate.SerialNumber), FileMode.Create))
            {
                PEMContainer.Save(PEMContainer.Certificate, certificate.RawData, file);
            }
        }

        public static X509Certificate LoadCertificate(byte[] serial)
        {
            using (FileStream file = new FileStream(GetCertificatePath(serial), FileMode.Open))
            {
                return new X509Certificate(PEMContainer.Load(file).First(n => n.Item1 == PEMContainer.Certificate).Item2);
            }
        }

        public static void SaveEncryptedPrivateKey(PKCS8.EncryptedPrivateKeyInfo key, byte[] serial)
        {
            using (FileStream file = new FileStream(GetPrivateKeyPath(serial), FileMode.Create))
            {
                PEMContainer.Save(PEMContainer.EncryptedPrivateKey, key.GetBytes(), file);
            }
        }

        public static PKCS8.EncryptedPrivateKeyInfo LoadEncryptedPrivateKey(byte[] serial)
        {
            using (FileStream file = new FileStream(GetPrivateKeyPath(serial), FileMode.Open))
            {
                return new PKCS8.EncryptedPrivateKeyInfo(PEMContainer.Load(file).First(n => n.Item1 == PEMContainer.EncryptedPrivateKey).Item2);
            }
        }
    }
}
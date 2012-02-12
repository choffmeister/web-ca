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

        public static void AddCertificate(X509Certificate certificate, string certificatePath, string keyPath)
        {
            bool isCertificateAuthority = false;

            foreach (X509Extension ext in certificate.Extensions)
            {
                if (ext.Name == "2.5.29.19" && new BasicConstraintsExtension(ext).CertificateAuthority)
                {
                    isCertificateAuthority = true;
                    break;
                }
            }

            File.AppendAllText(SerialsPath, string.Format(@"{6} {0} ""{1}"" {2:yyyy-MM-ddTHH:mm:ssZ} {3:yyyy-MM-ddTHH:mm:ssZ} ""{4}"" ""{5}""" + "\n",
                X509Extensions.FormatSerialNumber(certificate.SerialNumber),
                certificate.SubjectName,
                certificate.ValidFrom.ToUniversalTime(),
                certificate.ValidUntil.ToUniversalTime(),
                certificatePath,
                keyPath,
                isCertificateAuthority ? "#" : " "
            ));
        }

        public static string GetCertificatePath(string serial)
        {
            var elements = ListCertificates().ToList();
            SerialListEntry entry = elements.SingleOrDefault(n => n.SerialNumber.Replace(":", "") == serial);

            return entry != null ? entry.CertificatePath : null;
        }

        public static string GetPrivateKeyPath(string serial)
        {
            var elements = ListCertificates().ToList();
            SerialListEntry entry = elements.SingleOrDefault(n => n.SerialNumber.Replace(":", "") == serial);

            return entry != null ? entry.PrivateKeyPath : null;
        }

        public static X509Certificate GetCertificate(string serial)
        {
            return LoadCertificate(GetCertificatePath(serial));
        }

        public static PKCS8.PrivateKeyInfo GetPrivateKey(string serial)
        {
            return LoadPrivateKey(GetPrivateKeyPath(serial));
        }

        public static PKCS8.EncryptedPrivateKeyInfo GetEncryptedPrivateKey(string serial)
        {
            return LoadEncryptedPrivateKey(GetPrivateKeyPath(serial));
        }

        public static IEnumerable<SerialListEntry> ListCertificates()
        {
            string[] lines = File.ReadAllLines(SerialsPath);

            Regex regex = new Regex(@"^\s*(?<IsCertificateAuthority>#)?\s+(?<SerialNumber>[^\s]+)\s+""(?<SubjectName>.+)""\s+(?<NotBefore>[^\s]+)\s+(?<NotAfter>[^\s]+)\s+""(?<CertificatePath>.+)""\s+""(?<PrivateKeyPath>.+)""\s*$");

            return lines.Select(n =>
            {
                Match match = regex.Match(n);

                if (!match.Success)
                    return null;

                return new SerialListEntry()
                {
                    SerialNumber = match.Groups["SerialNumber"].Value,
                    IsCertificateAuthority = match.Groups["IsCertificateAuthority"].Value == "#",
                    SubjectName = match.Groups["SubjectName"].Value,
                    NotBefore = Convert.ToDateTime(match.Groups["NotBefore"].Value.Replace("T", " ").Replace("Z", "")),
                    NotAfter = Convert.ToDateTime(match.Groups["NotAfter"].Value.Replace("T", " ").Replace("Z", "")),
                    CertificatePath = match.Groups["CertificatePath"].Value,
                    PrivateKeyPath = match.Groups["PrivateKeyPath"].Value
                };
            }).Where(n => n != null);
        }

        public static void SaveCertificate(X509Certificate certificate, string certificatePath)
        {
            using (FileStream file = new FileStream(certificatePath, FileMode.Create))
            {
                PEMContainer.Save(PEMContainer.Certificate, certificate.RawData, file);
            }
        }

        public static X509Certificate LoadCertificate(string certificatePath)
        {
            using (FileStream file = new FileStream(certificatePath, FileMode.Open))
            {
                return new X509Certificate(PEMContainer.Load(file).First(n => n.Item1 == PEMContainer.Certificate).Item2);
            }
        }

        public static void SavePrivateKey(PKCS8.PrivateKeyInfo key, string keyPath)
        {
            using (FileStream file = new FileStream(keyPath, FileMode.Create))
            {
                PEMContainer.Save(PEMContainer.PrivateKey, key.GetBytes(), file);
            }
        }

        public static PKCS8.PrivateKeyInfo LoadPrivateKey(string privateKeyPath)
        {
            using (FileStream file = new FileStream(privateKeyPath, FileMode.Open))
            {
                return new PKCS8.PrivateKeyInfo(PEMContainer.Load(file).First(n => n.Item1 == PEMContainer.PrivateKey).Item2);
            }
        }

        public static void SaveEncryptedPrivateKey(PKCS8.EncryptedPrivateKeyInfo key, string keyPath)
        {
            using (FileStream file = new FileStream(keyPath, FileMode.Create))
            {
                PEMContainer.Save(PEMContainer.EncryptedPrivateKey, key.GetBytes(), file);
            }
        }

        public static PKCS8.EncryptedPrivateKeyInfo LoadEncryptedPrivateKey(string encryptedPrivateKeyPath)
        {
            using (FileStream file = new FileStream(encryptedPrivateKeyPath, FileMode.Open))
            {
                return new PKCS8.EncryptedPrivateKeyInfo(PEMContainer.Load(file).First(n => n.Item1 == PEMContainer.EncryptedPrivateKey).Item2);
            }
        }

        public class SerialListEntry
        {
            public string SerialNumber { get; set; }

            public bool IsCertificateAuthority { get; set; }

            public string SubjectName { get; set; }

            public DateTime NotBefore { get; set; }

            public DateTime NotAfter { get; set; }

            public string CertificatePath { get; set; }

            public string PrivateKeyPath { get; set; }
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using WebCA.Frontend.Extensions;

namespace WebCA.Frontend
{
    public static class CertificateKeyManager
    {
        public static string SerialsPath
        {
            get { return Path.Combine(HttpContext.Current.Server.MapPath("~/App_Data"), "serials.txt"); }
        }

        public static void AddCertificate(X509Certificate certificate, string certificatePath, string keyPath)
        {
            File.AppendAllText(SerialsPath, string.Format(@"{0} ""{1}"" {2:yyyy-MM-ddTHH:mm:ssZ} {3:yyyy-MM-ddTHH:mm:ssZ} ""{4}"" ""{5}""" + "\n",
                X509Extensions.FormatSerialNumber(certificate.SerialNumber),
                certificate.SubjectName,
                certificate.ValidFrom.ToUniversalTime(),
                certificate.ValidUntil.ToUniversalTime(),
                certificatePath,
                keyPath
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

            Regex regex = new Regex(@"^(?<SerialNumber>[^\s]+)\s""(?<SubjectName>.+)""\s(?<NotBefore>[^\s]+)\s(?<NotAfter>[^\s]+)\s""(?<CertificatePath>.+)""\s""(?<PrivateKeyPath>.+)""$");

            return lines.Select(n =>
            {
                Match match = regex.Match(n);

                if (!match.Success)
                    return null;

                return new SerialListEntry()
                {
                    SerialNumber = match.Groups["SerialNumber"].Value,
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
            File.WriteAllText(certificatePath,
                "-----BEGIN CERTIFICATE-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(certificate.RawData), 64)) +
                "\n-----END CERTIFICATE-----");
        }

        public static X509Certificate LoadCertificate(string certificatePath)
        {
            Regex regex = new Regex(@"-----BEGIN CERTIFICATE-----(?<Base64>[a-zA-Z0-9+/\s]*)-----END CERTIFICATE-----");
            Match match = regex.Match(File.ReadAllText(certificatePath));

            if (match.Success)
            {
                return new X509Certificate(Convert.FromBase64String(match.Groups["Base64"].Value));
            }
            else
            {
                return null;
            }
        }

        public static void SavePrivateKey(PKCS8.PrivateKeyInfo key, string keyPath)
        {
            File.WriteAllText(keyPath,
                "-----BEGIN PRIVATE KEY-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(key.GetBytes()), 64)) +
                "\n-----END PRIVATE KEY-----");
        }

        public static PKCS8.PrivateKeyInfo LoadPrivateKey(string certificatePath)
        {
            Regex regex = new Regex(@"-----BEGIN PRIVATE KEY-----(?<Base64>[a-zA-Z0-9+/\s]*)-----END PRIVATE KEY-----");
            Match match = regex.Match(File.ReadAllText(certificatePath));

            if (match.Success)
            {
                return new PKCS8.PrivateKeyInfo(Convert.FromBase64String(match.Groups["Base64"].Value));
            }
            else
            {
                return null;
            }
        }

        public static void SaveEncryptedPrivateKey(PKCS8.EncryptedPrivateKeyInfo key, string keyPath)
        {
            File.WriteAllText(keyPath,
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(key.GetBytes()), 64)) +
                "\n-----END ENCRYPTED PRIVATE KEY-----");
        }

        public static PKCS8.EncryptedPrivateKeyInfo LoadEncryptedPrivateKey(string certificatePath)
        {
            Regex regex = new Regex(@"-----BEGIN ENCRYPTED PRIVATE KEY-----(?<Base64>[a-zA-Z0-9+/\s]*)-----END ENCRYPTED PRIVATE KEY-----");
            Match match = regex.Match(File.ReadAllText(certificatePath));

            if (match.Success)
            {
                return new PKCS8.EncryptedPrivateKeyInfo(Convert.FromBase64String(match.Groups["Base64"].Value));
            }
            else
            {
                return null;
            }
        }

        public static IEnumerable<string> Split(string str, int chunkSize)
        {
            for (int i = 0; i < str.Length; i += chunkSize)
            {
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
            }
        }

        public class SerialListEntry
        {
            public string SerialNumber { get; set; }

            public string SubjectName { get; set; }

            public DateTime NotBefore { get; set; }

            public DateTime NotAfter { get; set; }

            public string CertificatePath { get; set; }

            public string PrivateKeyPath { get; set; }
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;
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
            File.WriteAllText(certificatePath,
                "-----BEGIN CERTIFICATE-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(certificate.RawData), 64)) +
                "\n-----END CERTIFICATE-----");
        }

        public static X509Certificate LoadCertificate(string certificatePath)
        {
            return new X509Certificate(GetFirstPemBlock(File.ReadAllLines(certificatePath), "CERTIFICATE"));
        }

        public static void SavePrivateKey(PKCS8.PrivateKeyInfo key, string keyPath)
        {
            File.WriteAllText(keyPath,
                "-----BEGIN PRIVATE KEY-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(key.GetBytes()), 64)) +
                "\n-----END PRIVATE KEY-----");
        }

        public static PKCS8.PrivateKeyInfo LoadPrivateKey(string privateKeyPath)
        {
            return new PKCS8.PrivateKeyInfo(GetFirstPemBlock(File.ReadAllLines(privateKeyPath), "PRIVATE KEY"));
        }

        public static void SaveEncryptedPrivateKey(PKCS8.EncryptedPrivateKeyInfo key, string keyPath)
        {
            File.WriteAllText(keyPath,
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                string.Join("\n", Split(Convert.ToBase64String(key.GetBytes()), 64)) +
                "\n-----END ENCRYPTED PRIVATE KEY-----");
        }

        public static PKCS8.EncryptedPrivateKeyInfo LoadEncryptedPrivateKey(string encryptedPrivateKeyPath)
        {
            return new PKCS8.EncryptedPrivateKeyInfo(GetFirstPemBlock(File.ReadAllLines(encryptedPrivateKeyPath), "ENCRYPTED PRIVATE KEY"));
        }

        public static byte[] GetFirstPemBlock(string[] lines, string name)
        {
            string base64 = null;
            bool started = false;

            for (int i = 0; i < lines.Length; i++)
            {
                if (!started && lines[i] == "-----BEGIN " + name + "-----")
                {
                    started = true;
                }
                else if (started && lines[i] == "-----END " + name + "-----")
                {
                    break;
                }
                else
                {
                    base64 += lines[i];
                }
            }

            return Convert.FromBase64String(base64);
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

            public bool IsCertificateAuthority { get; set; }

            public string SubjectName { get; set; }

            public DateTime NotBefore { get; set; }

            public DateTime NotAfter { get; set; }

            public string CertificatePath { get; set; }

            public string PrivateKeyPath { get; set; }
        }
    }
}
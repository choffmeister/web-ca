using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;

namespace WebCA.Security.Extensions
{
    public static class X509Extensions
    {
        private static readonly char[] _charactersToEscape = { '\\', ',', '+', '"', '<', '>', ';' };

        public static X509Certificate CreateCertificate(string subjectName, bool isCertificateAuthority, DateTime notBefore, DateTime notAfter, RSA key,
            string[] extendedKeyUsage = null)
        {
            string name = subjectName;

            X509CertificateBuilder builder = new X509CertificateBuilder(3);
            builder.SerialNumber = GenerateSerialNumber();
            builder.NotBefore = notBefore;
            builder.NotAfter = notAfter;
            builder.IssuerName = name;
            builder.SubjectName = name;
            builder.SubjectPublicKey = key;
            builder.Hash = "SHA1";

            if (isCertificateAuthority)
            {
                builder.Extensions.Add(new BasicConstraintsExtension() { CertificateAuthority = true });
            }

            if (extendedKeyUsage != null && extendedKeyUsage.Length > 0)
            {
                ExtendedKeyUsageExtension eku = new ExtendedKeyUsageExtension();
                eku.KeyPurpose.AddRange(extendedKeyUsage);
                builder.Extensions.Add(eku);
            }

            return new X509Certificate(builder.Sign(key));
        }

        public static X509Certificate CreateSignedCertificate(this X509Certificate certificate, X509Certificate issuerCertificate, PKCS8.PrivateKeyInfo issuerPrivateKey)
        {
            X509CertificateBuilder builder = new X509CertificateBuilder(3);
            builder.SerialNumber = GenerateSerialNumber();
            builder.NotBefore = certificate.ValidFrom;
            builder.NotAfter = certificate.ValidUntil;
            builder.IssuerName = issuerCertificate.SubjectName;
            builder.SubjectName = certificate.SubjectName;
            builder.SubjectPublicKey = certificate.RSA;
            builder.Hash = "SHA1";
            builder.Extensions.AddRange(certificate.Extensions);

            return new X509Certificate(builder.Sign(PKCS8.PrivateKeyInfo.DecodeRSA(issuerPrivateKey.PrivateKey)));
        }

        public static bool GetIsCertificateAuthority(this X509Certificate certificate)
        {
            foreach (X509Extension ext in certificate.Extensions)
            {
                if (ext.Name == "2.5.29.19" && new BasicConstraintsExtension(ext).CertificateAuthority)
                {
                    return true;
                }
            }

            return false;
        }

        public static byte[] GenerateSerialNumber()
        {
            byte[] serialNumber = Guid.NewGuid().ToByteArray();

            if ((serialNumber[0] & 0x80) == 0x80)

                serialNumber[0] -= 0x80;

            return serialNumber;
        }

        public static string FormatSerialNumber(this byte[] serialNumber, bool dropColons = false)
        {
            if (dropColons)
            {
                return string.Join("", serialNumber.Select(n => string.Format("{0:x2}", n)));
            }
            else
            {
                return string.Join(":", serialNumber.Select(n => string.Format("{0:x2}", n)));
            }
        }

        public static byte[] ParseSerialNumber(this string serialNumber)
        {
            serialNumber = serialNumber.Replace(":", "");

            return Enumerable.Range(0, serialNumber.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(serialNumber.Substring(x, 2), 16))
                .ToArray();
        }

        public static string BuildDistinguishedName(string country, string state, string locality, string organization, string organizationalUnit, string commonName)
        {
            string name = null;
            if (!string.IsNullOrEmpty(country)) name += string.Format("C={0},", EscapeDistinguishedNameComponent(country));
            if (!string.IsNullOrEmpty(state)) name += string.Format("ST={0},", EscapeDistinguishedNameComponent(state));
            if (!string.IsNullOrEmpty(locality)) name += string.Format("L={0},", EscapeDistinguishedNameComponent(locality));
            if (!string.IsNullOrEmpty(organization)) name += string.Format("O={0},", EscapeDistinguishedNameComponent(organization));
            if (!string.IsNullOrEmpty(organizationalUnit)) name += string.Format("OU={0},", EscapeDistinguishedNameComponent(organizationalUnit));
            if (!string.IsNullOrEmpty(commonName)) name += string.Format("CN={0},", EscapeDistinguishedNameComponent(commonName));
            name = name.Substring(0, name.Length - 1);

            return name;
        }

        public static string EscapeDistinguishedNameComponent(string value)
        {
            value = value.Trim();

            foreach (char c in _charactersToEscape)
            {
                value = value.Replace(c.ToString(), "\\" + c.ToString());
            }

            return value;
        }

        public static IEnumerable<Tuple<string, string>> ExtendedKeyUsage
        {
            get
            {
                return new Tuple<string, string>[] {
                    Tuple.Create("1.3.6.1.5.5.7.3.1", "Server authentication"),
                    Tuple.Create("1.3.6.1.5.5.7.3.2", "Client authentication"),
                    Tuple.Create("1.3.6.1.5.5.7.3.3", "Code signing"),
                    Tuple.Create("1.3.6.1.5.5.7.3.4", "Email Protection"),
                    Tuple.Create("1.3.6.1.5.5.7.3.5", "IPSec end system"),
                    Tuple.Create("1.3.6.1.5.5.7.3.6", "IPSec tunnel"),
                    Tuple.Create("1.3.6.1.5.5.7.3.7", "IPSec user"),
                    Tuple.Create("1.3.6.1.5.5.7.3.8", "Timestamping")
                };
            }
        }
    }
}
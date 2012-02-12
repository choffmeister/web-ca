﻿using System;
using System.Linq;
using System.Security.Cryptography;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;

namespace WebCA.Frontend.Extensions
{
    public static class X509Extensions
    {
        private static readonly char[] _charactersToEscape = { '\\', ',', '+', '"', '<', '>', ';' };

        public static X509Certificate CreateCertificate(string subjectName, bool isCertificateAuthority, DateTime notBefore, DateTime notAfter, RSA key)
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

            return new X509Certificate(builder.Sign(key));
        }

        public static X509Certificate CreateSignedCertificate(this X509Certificate certificate, X509Certificate issuerCertificate, PKCS8.PrivateKeyInfo issuerPrivateKey)
        {
            X509CertificateBuilder builder = new X509CertificateBuilder(3);
            builder.SerialNumber = certificate.SerialNumber;
            builder.NotBefore = certificate.ValidFrom;
            builder.NotAfter = certificate.ValidUntil;
            builder.IssuerName = issuerCertificate.SubjectName;
            builder.SubjectName = certificate.SubjectName;
            builder.SubjectPublicKey = certificate.RSA;
            builder.Hash = "SHA1";
            builder.Extensions.AddRange(certificate.Extensions);

            return new X509Certificate(builder.Sign(PKCS8.PrivateKeyInfo.DecodeRSA(issuerPrivateKey.PrivateKey)));
        }

        public static byte[] GenerateSerialNumber()
        {
            byte[] serialNumber = Guid.NewGuid().ToByteArray();

            if ((serialNumber[0] & 0x80) == 0x80)
                serialNumber[0] -= 0x80;

            return serialNumber;
        }

        public static string FormatSerialNumber(byte[] serialNumber)
        {
            return string.Join(":", serialNumber.Select(n => string.Format("{0:x2}", n)));
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
    }
}
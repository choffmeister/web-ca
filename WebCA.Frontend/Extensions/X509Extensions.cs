using System;
using System.Linq;
using System.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.X509.Extensions;

namespace WebCA.Frontend.Extensions
{
    public class X509Extensions
    {
        public static X509Certificate CreateRootCA(string commonName, DateTime notBefore, DateTime notAfter, RSA key)
        {
            string name = string.Format("CN={0}", commonName);

            X509CertificateBuilder builder = new X509CertificateBuilder(3);
            builder.SerialNumber = GenerateSerialNumber();
            builder.NotBefore = notBefore;
            builder.NotAfter = notAfter;
            builder.IssuerName = name;
            builder.SubjectName = name;
            builder.SubjectPublicKey = key;
            builder.Hash = "SHA1";
            builder.Extensions.Add(new BasicConstraintsExtension() { CertificateAuthority = true });

            return new X509Certificate(builder.Sign(key));
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
    }
}
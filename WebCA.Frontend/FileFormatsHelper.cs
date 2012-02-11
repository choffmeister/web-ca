using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Security.Cryptography;
using Mono.Security.X509;

namespace WebCA.Frontend
{
    public static class FileFormatsHelper
    {
        public static IEnumerable<object> ReadPem(byte[] data)
        {
            List<object> result = new List<object>();

            string[] lines = Encoding.UTF8.GetString(data)
                .Replace("\r\n", "\n")
                .Replace("\r", "\n")
                .Split(new char[] { '\n' })
                .Select(n => n.Trim())
                .Where(n => !string.IsNullOrEmpty(n))
                .ToArray();

            string typeString = null;
            StringBuilder dataStringBuilder = null;

            foreach (string line in lines)
            {
                if (typeString == null && line.Length >= 10 && line.Substring(0, 10) == "-----BEGIN")
                {
                    typeString = line.Substring(11, line.Length - 16);
                    dataStringBuilder = new StringBuilder();
                }
                else if (typeString != null && line.Length >= 8 && line.Substring(0, 8) == "-----END")
                {
                    byte[] dataBuffer = Convert.FromBase64String(dataStringBuilder.ToString());

                    switch (typeString)
                    {
                        case "RSA PUBLIC KEY": // PKCS#1 RSAPublicKey
                            throw new NotImplementedException();

                        case "PUBLIC KEY": // X.509 SubjectPublicKeyInfo
                            throw new NotImplementedException();

                        case "ENCRYPTED PRIVATE KEY": // PKCS#8 EncryptedPrivateKeyInfo
                            result.Add(GetPKCS8EncryptedPrivateKeyInfo(dataBuffer));
                            break;

                        case "RSA PRIVATE KEY": // PKCS#1 RSAPrivateKey
                            break;

                        case "PRIVATE KEY": // PKCS#8 PrivateKeyInfo
                            result.Add(GetPKCS8PrivateKeyInfo(dataBuffer));
                            break;

                        case "CERTIFICATE": // Certificate
                            result.Add(GetX509Certificate(dataBuffer));
                            break;

                        case "CERTIFICATE REQUEST": // Certificate Request
                            throw new NotImplementedException();

                        default:
                            throw new NotSupportedException(string.Format("PEM type '{0}' is not supported.", typeString));
                    }

                    dataStringBuilder = null;
                    typeString = null;
                }
                else if (dataStringBuilder != null)
                {
                    dataStringBuilder.Append(line);
                }
            }

            return result;
        }

        public static PKCS8.EncryptedPrivateKeyInfo GetPKCS8EncryptedPrivateKeyInfo(byte[] data)
        {
            return new PKCS8.EncryptedPrivateKeyInfo(data);
        }

        public static PKCS8.PrivateKeyInfo GetPKCS8PrivateKeyInfo(byte[] data)
        {
            return new PKCS8.PrivateKeyInfo(data);
        }

        public static X509Certificate GetX509Certificate(byte[] data)
        {
            return new X509Certificate(data);
        }
    }
}
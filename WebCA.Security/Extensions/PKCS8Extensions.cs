using System.Security.Cryptography;
using Mono.Security.Cryptography;
using Mono.Security.X509;

namespace WebCA.Security.Extensions
{
    public static class PKCS8Extensions
    {
        public static PKCS8.PrivateKeyInfo Decrypt(this PKCS8.EncryptedPrivateKeyInfo keyEnc, string password)
        {
            PKCS12 pkcs12 = new PKCS12();
            pkcs12.Password = password;

            return new PKCS8.PrivateKeyInfo(pkcs12.Decrypt(keyEnc.Algorithm, keyEnc.Salt, keyEnc.IterationCount, keyEnc.EncryptedData));
        }

        public static PKCS8.EncryptedPrivateKeyInfo Encrypt(this PKCS8.PrivateKeyInfo key, string password,
            string algorithm = PKCS12.pbeWithSHAAnd3KeyTripleDESCBC, int saltLength = 8, int iterationCount = 2048)
        {
            PKCS12 pkcs12 = new PKCS12();
            pkcs12.Password = password;

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] salt = new byte[saltLength];
            rng.GetBytes(salt);

            if ((salt[0] & 0x80) == 0x80)
                salt[0] -= 0x80;

            PKCS8.EncryptedPrivateKeyInfo keyEnc = new PKCS8.EncryptedPrivateKeyInfo();
            keyEnc.EncryptedData = pkcs12.Encrypt(algorithm, salt, iterationCount, key.GetBytes());
            keyEnc.Algorithm = algorithm;
            keyEnc.IterationCount = iterationCount;
            keyEnc.Salt = salt;

            return keyEnc;
        }

        public static PKCS8.PrivateKeyInfo CreateFromRSA(RSA rsa)
        {
            PKCS8.PrivateKeyInfo privateKey = new PKCS8.PrivateKeyInfo();
            privateKey.PrivateKey = PKCS8.PrivateKeyInfo.Encode(rsa);
            privateKey.Version = 2;
            privateKey.Algorithm = "1.2.840.113549.1.1.1";

            return privateKey;
        }
    }
}
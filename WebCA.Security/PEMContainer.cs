using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace WebCA.Frontend
{
    public class PEMContainer : IEnumerable<Tuple<string, byte[]>>
    {
        public static readonly string Certificate = "CERTIFICATE";
        public static readonly string CertificateRequest = "CERTIFICATE REQUEST";

        public static readonly string PublicKey = "PUBLIC KEY";
        public static readonly string PrivateKey = "PRIVATE KEY";
        public static readonly string EncryptedPrivateKey = "ENCRYPTED PRIVATE KEY";

        public static readonly string RSAPublicKey = "RSA PUBLIC KEY";
        public static readonly string RSAPrivateKey = "RSA PRIVATE KEY";

        private List<Tuple<string, byte[]>> _blocks = new List<Tuple<string, byte[]>>();

        public PEMContainer()
        {
        }

        public PEMContainer(string type, byte[] buffer)
        {
            this.AddBlock(type, buffer);
        }

        public void AddBlock(string type, byte[] buffer)
        {
            _blocks.Add(Tuple.Create(type, buffer));
        }

        public void RemoveBlock(int index)
        {
            _blocks.RemoveAt(index);
        }

        public static PEMContainer Load(Stream stream)
        {
            PEMContainer pem = new PEMContainer();

            List<string> lines = new List<string>((int)stream.Length / 64);

            using (StreamReader reader = new StreamReader(stream))
            {
                while (!reader.EndOfStream)
                {
                    lines.Add(reader.ReadLine().Trim());
                }
            }

            pem._blocks.AddRange(PEMBlocks(lines));

            return pem;
        }

        public static void Save(string type, byte[] buffer, Stream stream)
        {
            PEMContainer pem = new PEMContainer(type, buffer);
            pem.Save(stream);
        }

        public static byte[] Save(string type, byte[] buffer)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                PEMContainer pem = new PEMContainer(type, buffer);
                pem.Save(stream);

                byte[] result = new byte[(int)stream.Length];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(result, 0, (int)stream.Length);

                return result;
            }
        }

        public void Save(Stream stream)
        {
            using (NotClosingStreamWriter writer = new NotClosingStreamWriter(stream))
            {
                foreach (var block in _blocks)
                {
                    writer.WriteLine(string.Format("-----BEGIN {0}-----", block.Item1));

                    foreach (var base64line in Split(Convert.ToBase64String(block.Item2), 64))
                    {
                        writer.WriteLine(base64line);
                    }

                    writer.WriteLine(string.Format("-----END {0}-----", block.Item1));
                    writer.WriteLine();
                }
            }
        }

        public static IEnumerable<Tuple<string, byte[]>> PEMBlocks(IEnumerable<string> lines)
        {
            List<byte> buffer = null;
            string type = null;

            foreach (string line in lines)
            {
                if (buffer == null && line.StartsWith("-----BEGIN ") && line.EndsWith("-----"))
                {
                    buffer = new List<byte>(2048 / 64);
                    type = line.Substring(11, line.Length - 16);
                }
                else if (buffer != null && line == "-----END " + type + "-----")
                {
                    yield return Tuple.Create(type, buffer.ToArray());
                    buffer = null;
                    type = null;
                }
                else if (line.Length == 0)
                {
                }
                else
                {
                    buffer.AddRange(Convert.FromBase64String(line));
                }
            }
        }

        public static IEnumerable<string> Split(string str, int chunkSize)
        {
            for (int i = 0; i < str.Length; i += chunkSize)
            {
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
            }
        }

        public IEnumerator<Tuple<string, byte[]>> GetEnumerator()
        {
            return _blocks.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _blocks.GetEnumerator();
        }
    }

    public class NotClosingStreamWriter : StreamWriter
    {
        public NotClosingStreamWriter(Stream stream)
            : base(stream)
        {
        }

        protected override void Dispose(bool disposing)
        {
            this.Flush();
            base.Dispose(false);
        }
    }
}
using System;
using System.Text;
using Mono.Security;

namespace WebCA.Frontend.Extensions
{
    public static class ASN1Extensions
    {
        public static StringBuilder ConvertToStringTree(this ASN1 asn1)
        {
            StringBuilder stringBuilder = new StringBuilder();

            asn1.ConvertToStringTree(0, stringBuilder);

            return stringBuilder;
        }

        private static void ConvertToStringTree(this ASN1 asn1, int level, StringBuilder stringBuilder)
        {
            string indent = string.Empty.PadLeft(level * 4);

            switch (asn1.Tag)
            {
                case 1:
                    stringBuilder.AppendLine(string.Format("{0}Boolean: {1}", indent, asn1.Value[0] != 0 ? "true" : "false"));
                    break;
                case 2:
                    if (asn1.Value.Length <= 16)
                    {
                        stringBuilder.AppendLine(string.Format("{0}Integer: {1} (0x{2})", indent, ASN1Convert.ToInt32(asn1), BitConverter.ToString(asn1.Value)));
                    }
                    else
                    {
                        stringBuilder.Append(string.Format("{0}Integer:", indent));

                        for (int i = 0; i < asn1.Value.Length; i++)
                        {
                            if (i % 16 == 0)
                            {
                                stringBuilder.AppendLine();
                                stringBuilder.Append(indent + "    ");
                            }

                            stringBuilder.Append(string.Format("{0:x2}:", asn1.Value[i]));
                        }

                        stringBuilder.AppendLine();
                    }
                    break;
                case 4:
                    stringBuilder.AppendLine(string.Format("{0}Inner object:", indent));
                    try
                    {
                        ConvertToStringTree(new ASN1(asn1.Value), level + 1, stringBuilder);
                    }
                    catch (Exception ex)
                    {
                        stringBuilder.AppendLine(string.Format("{0}ERROR!: {1}", indent + "    ", ex.Message));
                    }
                    break;
                case 5:
                    stringBuilder.AppendLine(string.Format("{0}Null", indent));
                    break;
                case 6:
                    stringBuilder.AppendLine(string.Format("{0}Identifier: {1}", indent, ASN1Convert.ToOid(asn1)));
                    break;
                case 12:
                    stringBuilder.AppendLine(string.Format("{0}String: {1}", indent, Encoding.UTF8.GetString(asn1.Value)));
                    break;
                case 48:
                    stringBuilder.AppendLine(string.Format("{0}Node: ", indent));
                    break;
                default:
                    stringBuilder.AppendLine(string.Format("{0}Unknown node ({2}):{1}", indent, BitConverter.ToString(asn1.Value), asn1.Tag));
                    break;
            }

            for (int i = 0; i < asn1.Count; i++)
            {
                ConvertToStringTree(asn1[i], level + 1, stringBuilder);
            }
        }
    }
}
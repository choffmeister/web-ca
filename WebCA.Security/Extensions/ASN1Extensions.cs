using System;
using System.Text;
using Mono.Security;

namespace WebCA.Security.Extensions
{
    public static class ASN1Extensions
    {
        public static string GetCommonName(this ASN1 name)
        {
            for (int i = 0; i < name.Count; i++)
            {
                ASN1 entry = name[i];

                for (int j = 0; j < entry.Count; j++)
                {
                    ASN1 aSN = entry[j];
                    ASN1 aSN2 = aSN[1];
                    ASN1 aSN3 = aSN[0];

                    if (aSN3 != null && ASN1Convert.ToOid(aSN3) == "2.5.4.3")
                    {
                        string text = null;

                        if (aSN2.Tag == 30)
                        {
                            StringBuilder stringBuilder = new StringBuilder();
                            for (int k = 1; k < aSN2.Value.Length; k += 2)
                            {
                                stringBuilder.Append((char)aSN2.Value[k]);
                            }
                            text = stringBuilder.ToString();
                        }
                        else
                        {
                            if (aSN2.Tag == 20)
                            {
                                text = Encoding.UTF7.GetString(aSN2.Value);
                            }
                            else
                            {
                                text = Encoding.UTF8.GetString(aSN2.Value);
                            }
                        }

                        return text;
                    }
                }
            }

            return null;
        }

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
                    stringBuilder.AppendLine(string.Format("{0}- Boolean: {1}", indent, asn1.Value[0] != 0 ? "true" : "false"));
                    break;
                case 2:
                    if (asn1.Value.Length <= 16)
                    {
                        stringBuilder.AppendLine(string.Format("{0}- Integer: {1} (0x{2})", indent, ASN1Convert.ToInt32(asn1), BitConverter.ToString(asn1.Value).Replace("-", "").ToLower()));
                    }
                    else
                    {
                        stringBuilder.Append(string.Format("{0}- Integer:", indent));

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
                    stringBuilder.AppendLine(string.Format("{0}- Inner object:", indent));
                    try
                    {
                        ConvertToStringTree(new ASN1(asn1.Value), level + 1, stringBuilder);
                    }
                    catch (Exception ex)
                    {
                        stringBuilder.AppendLine(string.Format("{0}- ERROR!: {1}", indent + "    ", ex.Message));
                    }
                    break;
                case 5:
                    stringBuilder.AppendLine(string.Format("{0}- Null", indent));
                    break;
                case 6:
                    stringBuilder.AppendLine(string.Format("{0}- Identifier: {1}", indent, ASN1Convert.ToOid(asn1)));
                    break;
                case 12:
                    stringBuilder.AppendLine(string.Format("{0}- String: {1}", indent, Encoding.UTF8.GetString(asn1.Value)));
                    break;
                case 19:
                    stringBuilder.AppendLine(string.Format("{0}- String: {1}", indent, Encoding.UTF8.GetString(asn1.Value)));
                    break;
                case 20:
                    stringBuilder.AppendLine(string.Format("{0}- String: {1}", indent, Encoding.UTF7.GetString(asn1.Value)));
                    break;
                case 23:
                    stringBuilder.AppendLine(string.Format("{0}- UTC Time: {1}", indent, ASN1Convert.ToDateTime(asn1)));
                    break;
                case 48:
                    stringBuilder.AppendLine(string.Format("{0}- Node: ", indent));
                    break;
                default:
                    stringBuilder.Append(string.Format("{0}- Unknown node ({1}):", indent, asn1.Tag));

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

                    break;
            }

            for (int i = 0; i < asn1.Count; i++)
            {
                ConvertToStringTree(asn1[i], level + 1, stringBuilder);
            }
        }
    }
}
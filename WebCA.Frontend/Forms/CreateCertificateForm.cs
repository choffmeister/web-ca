using System;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace WebCA.Frontend.Forms
{
    public class CreateCertificateForm
    {
        [StringLength(4)]
        public string Country { get; set; }

        [StringLength(128)]
        public string State { get; set; }

        [StringLength(128)]
        public string Locality { get; set; }

        [StringLength(128)]
        public string Organization { get; set; }

        [StringLength(128)]
        public string OrganizationalUnit { get; set; }

        [StringLength(128)]
        [Required]
        public string CommonName { get; set; }

        public bool IsCertificateAuthority { get; set; }

        public DateTime NotBefore { get; set; }

        public DateTime NotAfter { get; set; }

        [StringLength(128)]
        [DataType(DataType.Password)]
        [Required]
        public string PrivateKeyPassphrase { get; set; }

        [StringLength(128)]
        [DataType(DataType.Password)]
        [Required]
        [Compare("PrivateKeyPassphrase", ErrorMessage = "The passphrase and confirmation password do not match.")]
        public string PrivateKeyPassphraseConfirmation { get; set; }
    }
}
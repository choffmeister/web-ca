using System;
using System.ComponentModel.DataAnnotations;

namespace WebCA.Frontend.Forms
{
    public class CreateRootCAForm
    {
        [StringLength(128)]
        [Required]
        public string CommonName { get; set; }

        public DateTime NotBefore { get; set; }

        public DateTime NotAfter { get; set; }

        [StringLength(128)]
        [Required]
        public string PrivateKeyPassphrase { get; set; }
    }
}
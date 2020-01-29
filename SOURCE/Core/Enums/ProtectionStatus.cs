using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BitlockerManager.Enums
{
    /// <summary>
    /// Specifies whether the volume and the encryption key (if any) are secured.
    /// </summary>
    public enum ProtectionStatus
    {
        /// <summary>
        /// PROTECTION OFF
        /// For a standard HDD:
        /// The volume is unencrypted, partially encrypted, or the volume's encryption key is available in the clear on the hard disk.
        /// The encryption key is available in the clear on the hard disk if key protectors have been disabled by using the
        /// DisableKeyProtectors method or if no key protectors have been specified by using the following methods (WMI):
        /// ProtectKeyWithCertificateFile
        /// ProtectKeyWithCertificateThumbprint
        /// ProtectKeyWithExternalKey
        /// ProtectKeyWithNumericalPassword
        /// ProtectKeyWithPassphrase
        /// ProtectKeyWithTPM
        /// ProtectKeyWithTPMAndPIN
        /// ProtectKeyWithTPMAndPINAndStartupKey
        /// ProtectKeyWithTPMAndStartupKey
        /// For an EHDD:
        /// The band for the volume is perpetually unlocked, has no key manager, or is managed by a third party key manager.
        /// This can also mean that the band is managed by BitLocker but the DisableKeyProtectors method has been called and the drive is suspended.
        /// </summary>
        Unprotected = 0,

        /// <summary>
        /// PROTECTION ON
        /// For a standard HDD:
        /// The volume is fully encrypted and the encryption key for the volume is not available in the clear on the hard disk.
        /// For an EHDD:
        /// BitLocker is the key manager for the band. The drive can be locked or unlocked but cannot be perpetually unlocked.
        /// </summary>
        Protected = 1,

        /// <summary>
        /// The volume protection status cannot be determined. This can be caused by the volume being in a locked state.
        /// Windows Vista Ultimate, Windows Vista Enterprise and Windows Server 2008: This value is not supported. This value is supported beginning with Windows 7 and Windows Server 2008 R2.
        /// </summary>
        Unknown = 2
    }
}

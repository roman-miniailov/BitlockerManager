// --------------------------------------------------------------------------------------------------------------------
// The MIT License (MIT)
//
// Copyright © 2015-2020 Roman Minyaylov (roman.minyaylov@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”),
// to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// --------------------------------------------------------------------------------------------------------------------

#pragma warning disable CA1303 // Do not pass literals as localized parameters

namespace BitLockerManager
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Management;
    using System.Security.Principal;

    using BitlockerManager;
    using BitlockerManager.Enums;

    /// <summary>
    /// BitLocker manager.
    /// </summary>
    public partial class BitLockerManager
    {
        private ManagementClass _wmiClass;

        private ManagementObject _vol;

        public string DeviceID { get; private set; }

        public string PersistentVolumeID { get; private set; }

        public BitLockerManager(DriveInfo drive)
        {
            if (drive == null)
            {
                throw new Exception("Drive can't be null!");
            }

            var path = new ManagementPath
            {
                NamespacePath = "\\ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
                ClassName = "Win32_EncryptableVolume"
            };

            _wmiClass = new ManagementClass(path);

            foreach (ManagementObject vol in _wmiClass.GetInstances())
            {
                var letterObj = vol["DriveLetter"];
                if (letterObj == null)
                {
                    continue;
                }

                var letter = letterObj.ToString();

                if (drive.Name.StartsWith(letter, StringComparison.OrdinalIgnoreCase))
                {
                    _vol = vol;

                    PersistentVolumeID = (string)_vol["PersistentVolumeID"];
                    DeviceID = (string)_vol["DeviceID"];

                    return;
                }
            }


            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "No drive found for {0}.", drive));
        }

        public bool IsLocked()
        {
            using (var inParams = _vol.GetMethodParameters("GetLockStatus"))
            {
                using (var outParams = _vol.InvokeMethod("GetLockStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            var lockStatus = (uint)outParams["LockStatus"];
                            return lockStatus == 1;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Unlock drive with passphrase.
        /// </summary>
        /// <param name="password">
        /// Password.
        /// </param>
        public void UnlockDriveWithPassphrase(string password)
        {
            var status = (uint)_vol["ProtectionStatus"];
            if (status == 1 || status == 2)
            {
                using (var inParams = _vol.GetMethodParameters("UnlockWithPassphrase"))
                {
                    inParams["Passphrase"] = password;
                    using (var outParams = _vol.InvokeMethod("UnlockWithPassphrase", inParams, null))
                    {
                        if (outParams == null)
                        {
                            throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                        }

                        var result = (uint)outParams["returnValue"];
                        switch (result)
                        {
                            case 0: // S_OK
                                return;
                            case 0x80310008: // FVE_E_NOT_ACTIVATED
                                throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.").SetCode(0x80310008);
                            case 0x8031006C: // FVE_E_FIPS_PREVENTS_PASSPHRASE
                                throw new InvalidOperationException("The group policy setting that requires FIPS compliance prevented the passphrase from being generated or used.").SetCode(0x8031006C);
                            case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                                throw new InvalidOperationException("The passphrase provided does not meet the minimum or maximum length requirements.").SetCode(0x80310080);
                            case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                                throw new InvalidOperationException("The passphrase does not meet the complexity requirements set by the administrator in group policy.").SetCode(0x80310081);
                            case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                                throw new InvalidOperationException("The volume cannot be unlocked with the provided information.").SetCode(0x80310027);
                            case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                                throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.").SetCode(0x80310033);
                            default:
                                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                        }
                    }
                }
            }
            else
            {
                throw new InvalidOperationException("Not an unlocked BitLocker drive.");
            }
        }

        /// <summary>
        /// Unlock drive with numerical password.
        /// </summary>
        /// <param name="password">
        /// Password.
        /// </param>
        public void UnlockDriveWithNumericalPassword(string password)
        {
            var status = (uint)_vol["ProtectionStatus"];
            if (status == 1 || status == 2)
            {
                using (var inParams = _vol.GetMethodParameters("UnlockWithNumericalPassword"))
                {
                    inParams["NumericalPassword"] = password;
                    using (var outParams = _vol.InvokeMethod("UnlockWithNumericalPassword", inParams, null))
                    {
                        if (outParams == null)
                        {
                            throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                        }

                        var result = (uint)outParams["returnValue"];
                        switch (result)
                        {
                            case 0: // S_OK
                                return;
                            case 0x80310008: // FVE_E_NOT_ACTIVATED
                                throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.").SetCode(0x80310008);
                            case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                                throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.").SetCode(0x80310033);
                            case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                                throw new InvalidOperationException("The volume cannot be unlocked with the provided information.").SetCode(0x80310027);
                            case 0x80310035: // FVE_E_INVALID_PASSWORD_FORMAT
                                throw new InvalidOperationException("The NumericalPassword parameter does not have a valid format.").SetCode(0x80310035);
                            default:
                                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                        }
                    }
                }
            }
            else
            {
                throw new InvalidOperationException("Not an unlocked BitLocker drive.");
            }
        }

        /// <summary>
        /// The BackupRecoveryInformationToActiveDirectory method backs up recovery data to Active Directory.
        /// This method requires a numerical password protector to be present on the volume.
        /// Group Policy must also be configured to enable backup of recovery information to Active Directory.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// Volume Key Protector ID. A unique string identifier used to manage an encrypted volume key protector.
        /// This key protector must be a numerical password protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/backuprecoveryinformationtoactivedirectory-win32-encryptablevolume
        /// </remarks>
        public void BackupRecoveryInformationToActiveDirectory(string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("BackupRecoveryInformationToActiveDirectory"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("BackupRecoveryInformationToActiveDirectory", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x1: // S_FALSE
                            throw new InvalidOperationException("Group Policy does not permit the storage of recovery information to Active Directory.").SetCode(0x1);
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The specified key protector is not a numerical key protector. You must enter a numerical password protector.").SetCode(0x8031003A);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Changes an external key that is associated with an encrypted volume.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="newExternalKey">
        /// An array of bytes that specifies the 256-bit external key used to unlock the volume.
        /// </param>
        /// <param name="newVolumeKeyProtectorId">
        /// An updated unique string identifier that is used to manage an encrypted volume key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/changeexternalkey-win32-encryptablevolume
        /// </remarks>
        public void ChangeExternalKey(string volumeKeyProtectorId, byte[] newExternalKey, string newVolumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ChangeExternalKey"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                inParams["NewExternalKey"] = newExternalKey;
                inParams["NewVolumeKeyProtectorID"] = newVolumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("ChangeExternalKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The NewExternalKey parameter is not an array of size 32.").SetCode(0x80070057);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.").SetCode(0x80310030);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume.").SetCode(0x80310033);
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"Numerical Password\" or "
                                                                + "\"External Key\".Use either the ProtectKeyWithNumericalPassword or ProtectKeyWithExternalKey "
                                                                + "method to create a key protector of the appropriate type.").SetCode(0x8031003A);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Method uses the new passphrase to obtain a new derived key. After the derived key is calculated,
        /// the new derived key is used to secure the encrypted volume's master key.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier that is used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="newPassphrase">
        /// An updated string that specifies the passphrase.
        /// </param>
        /// <param name="newProtectorId">
        /// An updated unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/changepassphrase-win32-encryptablevolume
        /// </remarks>
        public void ChangePassphrase(string volumeKeyProtectorId, string newPassphrase, out string newProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ChangePassphrase"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                inParams["NewPassphrase"] = newPassphrase;
                using (var outParams = _vol.InvokeMethod("ChangePassphrase", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    newProtectorId = (string)outParams["NewProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is already locked by BitLocker Drive Encryption. You must unlock the drive from Control Panel.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310024: // FVE_E_OVERLAPPED_UPDATE
                            throw new InvalidOperationException("The control block for the encrypted volume was updated by another thread.").SetCode(0x80310024);
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The specified key protector is not of the correct type.").SetCode(0x8031003A);
                        case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                            throw new InvalidOperationException("The updated passphrase provided does not meet the minimum or maximum length requirements.").SetCode(0x80310080);
                        case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                            throw new InvalidOperationException("The updated passphrase does not meet the complexity requirements set by the administrator in group policy.").SetCode(0x80310081);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Changes the PIN associated with an encrypted volume. If the "Allow enhanced PINs for startup" group policy is enabled,
        /// a PIN can contain letters, symbols, and spaces in addition to numbers.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// The unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="newPIN">
        /// A user-specified personal identification string. This string must consist of a sequence of 4 to 20 digits or,
        /// if the "Allow enhanced PINs for startup" group policy is enabled, 4 to 20 letters, symbols, spaces, or numbers.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/changepin-win32-encryptablevolume
        /// </remarks>
        public void ChangePIN(string volumeKeyProtectorId, string newPIN)
        {
            using (var inParams = _vol.GetMethodParameters("ChangePIN"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                inParams["NewPIN"] = newPIN;
                using (var outParams = _vol.InvokeMethod("ChangePIN", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.").SetCode(0x80310030);
                        case 0x8031009A: // FVE_E_INVALID_PIN_CHARS
                            throw new InvalidOperationException("The NewPIN parameter contains characters that are not valid.When the \"Allow enhanced PINs for startup\""
                                                                + " Group Policy is disabled, only numbers are supported.").SetCode(0x8031009A);
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException(" The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"Numerical Password\" "
                                                                + "or \"External Key\".Use either the ProtectKeyWithNumericalPassword or ProtectKeyWithExternalKey method "
                                                                + "to create a key protector of the appropriate type.").SetCode(0x8031003A);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310068: // FVE_E_POLICY_INVALID_PIN_LENGTH
                            throw new InvalidOperationException(" The NewPIN parameter supplied is either longer than 20 characters, shorter than 4 characters, "
                                                                + "or shorter than the minimum length specified by Group Policy.").SetCode(0x80310068);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume.").SetCode(0x80310033);
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible Trusted Platform Module(TPM) is found on this computer.").SetCode(0x80284008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Removes all external keys and related information saved onto the currently running operating system volume that are used
        /// to automatically unlock data volumes.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/clearallautounlockkeys-win32-encryptablevolume
        /// </remarks>
        public void ClearAllAutoUnlockKeys()
        {
            using (var inParams = _vol.GetMethodParameters("ClearAllAutoUnlockKeys"))
            {
                using (var outParams = _vol.InvokeMethod("ClearAllAutoUnlockKeys", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310028: // FVE_E_NOT_OS_VOLUME
                            throw new InvalidOperationException("The method can only be run for the currently running operating system volume.").SetCode(0x80310028);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// begins decryption of a fully encrypted volume, or resumes decryption of a partially encrypted volume. When decryption is paused or in-progress,
        /// this method behaves the same as ResumeConversion.When encryption is paused or in-progress, this method reverts the encryption
        /// and begins decryption.After decryption completes, all key protectors on this volume are removed from the system and the volume
        /// converts to a standard NTFS file system.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/decrypt-win32-encryptablevolume
        /// </remarks>
        public void Decrypt()
        {
            using (var inParams = _vol.GetMethodParameters("Decrypt"))
            {
                using (var outParams = _vol.InvokeMethod("Decrypt", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310029: // FVE_E_AUTOUNLOCK_ENABLED
                            throw new InvalidOperationException("This volume cannot be decrypted because keys used to automatically unlock data"
                                                                + " volumes are available. Use ClearAllAutoUnlockKeys to remove these keys.").SetCode(0x80310029);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Deletes a given key protector for the volume.
        /// If an unencrypted volume has key protectors, when DeleteKeyProtector removes the last key protector, the volume reverts to a standard NTFS file system.
        /// If a volume has never been encrypted, deleting the key protector will revert to NTFS.
        /// If the volume is not yet fully decrypted, use DisableKeyProtectors before removing the volume's last key protector to ensure that encrypted portions of the volume remain accessible.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/deletekeyprotector-win32-encryptablevolume
        /// </remarks>
        public void DeleteKeyProtector(string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("DeleteKeyProtector"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("DeleteKeyProtector", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid key protector.").SetCode(0x80070057);
                        case 0x8031001D: // FVE_E_KEY_REQUIRED
                            throw new InvalidOperationException("The last key protector for a partially or fully encrypted volume cannot be removed if "
                                                                + "key protectors are enabled.Use DisableKeyProtectors before removing this last key protector"
                                                                + " to ensure that encrypted portions of the volume remain accessible.").SetCode(0x8031001D);
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("This key protector cannot be deleted because it is being used to automatically unlock the volume."
                                                                + " Use DisableAutoUnlock to disable automatic unlocking before deleting this key protector.").SetCode(0x8031001F);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Deletes all key protectors for the volume.
        /// If an unencrypted volume has key protectors, when DeleteKeyProtectors is run successfully the volume reverts to a standard NTFS file system.
        /// If the volume is not yet fully decrypted, use DisableKeyProtectors before running DeleteKeyProtectors to ensure that encrypted portions of the volume remain accessible.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/deletekeyprotectors-win32-encryptablevolume
        /// </remarks>
        public void DeleteKeyProtectors()
        {
            using (var inParams = _vol.GetMethodParameters("DeleteKeyProtectors"))
            {
                using (var outParams = _vol.InvokeMethod("DeleteKeyProtectors", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x8031001D: // FVE_E_KEY_REQUIRED
                            throw new InvalidOperationException("The last key protector for a partially or fully encrypted volume cannot be removed"
                                                                + " if key protectors are enabled.Use DisableKeyProtectors before removing this last key protector to ensure that encrypted portions"
                                                                + " of the volume remain accessible.").SetCode(0x8031001D);
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("Key protectors cannot be deleted because one of them is being used to automatically unlock the volume."
                                                                + " Use DisableAutoUnlock to disable automatic unlocking before running this method.").SetCode(0x8031001F);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Removes the external key saved onto the currently running operating system volume so that a data volume is not automatically unlocked when it
        /// is mounted, such as when removable memory devices are connected to the computer.
        /// If automatic unlocking is disabled or suspended, the methods UnlockWithExternalKey or UnlockWithNumericalPassword must be used to unlock the volume.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/disableautounlock-win32-encryptablevolume
        /// </remarks>
        public void DisableAutoUnlock()
        {
            using (var inParams = _vol.GetMethodParameters("DisableAutoUnlock"))
            {
                using (var outParams = _vol.InvokeMethod("DisableAutoUnlock", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;

                        case 0x80310017: // FVE_E_VOLUME_NOT_BOUND
                            throw new InvalidOperationException("Automatic unlocking on the volume is disabled.").SetCode(0x80310017);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310019: // FVE_E_NOT_DATA_VOLUME
                            throw new InvalidOperationException("The method cannot be run for the currently running operating system volume.").SetCode(0x80310019);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Disables or suspends all key protectors associated with this volume.
        /// </summary>
        /// <param name="disableCount">
        /// Integer that specifies the number of reboots for which the key protectors will be disabled. This parameter is only available on OS volumes.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/disablekeyprotectors-win32-encryptablevolume
        /// </remarks>
        public void DisableKeyProtectors(uint disableCount)
        {
            using (var inParams = _vol.GetMethodParameters("DisableKeyProtectors"))
            {
                inParams["DisableCount"] = disableCount;
                using (var outParams = _vol.InvokeMethod("DisableKeyProtectors", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Allows a data volume to be automatically unlocked when the volume is mounted.
        /// Automatic unlocking saves an external key to the operating system that can automatically unlock the volume onto the currently running operating system volume.
        /// To use this method, the operating system volume must already be protected by BitLocker Drive Encryption or must have encryption in progress.
        /// In addition, there must already exist an external key for the data volume. Use ProtectKeyWithExternalKey to create the external key that can automatically unlock the volume.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A string that identifies the key protector of the type "External Key" used to automatically unlock the volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/enableautounlock-win32-encryptablevolume
        /// </remarks>
        public void EnableAutoUnlock(string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("EnableAutoUnlock"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("EnableAutoUnlock", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid key protector of the type \"External Key\".").SetCode(0x80070057);
                        case 0x80310019: // FVE_E_NOT_DATA_VOLUME
                            throw new InvalidOperationException("The method cannot be run for the currently running operating system volume.").SetCode(0x80310019);
                        case 0x80310020: // FVE_E_OS_NOT_PROTECTED
                            throw new InvalidOperationException("The method cannot be run if the currently running operating system volume is not protected by BitLocker Drive Encryption "
                                                                + "or does not have encryption in progress.").SetCode(0x80310020);
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("Automatic unlocking on the volume has previously been enabled.").SetCode(0x8031001F);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Enables or resumes all disabled or suspended key protectors. You can use this method to reenable or resume BitLocker protection on an encrypted volume.
        /// This method ensures that the volume's encryption key is not exposed in the clear on the hard disk.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/enablekeyprotectors-win32-encryptablevolume
        /// </remarks>
        public void EnableKeyProtectors()
        {
            using (var inParams = _vol.GetMethodParameters("EnableKeyProtectors"))
            {
                using (var outParams = _vol.InvokeMethod("EnableKeyProtectors", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310007: // FVE_E_SECURE_KEY_REQUIRED
                            throw new InvalidOperationException("No key protectors exist on the volume. Use one of the following methods to specify key protectors for the volume: "
                                                                + "ProtectKeyWithCertificateFile, ProtectKeyWithCertificateThumbprint, ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword"
                                                                + "ProtectKeyWithPassphrase, ProtectKeyWithTPM, ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey").SetCode(0x80310007);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:

                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Begins encryption of a fully decrypted volume, or resumes encryption of a partially encrypted volume. When encryption is paused or in-progress,
        /// this method behaves the same as ResumeConversion. When decryption is paused or in-progress, this method stops the decryption and begins encryption.
        /// </summary>
        /// <param name="encryptionMethod">
        /// An unsigned integer that specifies the encryption algorithm and key size used to encrypt the volume. If this parameter is greater than zero and the volume
        /// is partially or fully encrypted, EncryptionMethod must match the volume's existing encryption method. If this parameter is greater than zero and the corresponding
        /// Group Policy setting is enabled with a valid value, EncryptionMethod must match the Group Policy setting.
        /// Default value for Windows 7 or below is: 1 (AES_128_WITH_DIFFUSER).
        /// Default value for Windows 8, Windows 8.1 or Windows 10, version 1507 is: 3 (AES_128).
        /// Default value for Windows 10, version 1511 or above is: 6 (XTS_AES_128).
        /// </param>
        /// <param name="encryptionFlags">Flags that describe the encryption behavior.
        /// Windows 7, Windows Server 2008 R2, Windows Vista Enterprise and Windows Server 2008: This parameter is not available.
        /// A combination of 32 bits with following bits currently defined.
        /// Value:
        /// 0x00000001 - Perform volume encryption in data-only encryption mode when starting new encryption process. If encryption has been paused or stopped,
        /// calling the Encrypt method effectively resumes conversion and the value of this bit is ignored. This bit only has effect when either the Encrypt or
        /// EncryptAfterHardwareTest methods start encryption from the fully decrypted state, decryption in progress state, or decryption paused state. If this bit
        /// is zero, meaning that it is not set, when starting new encryption process, then full mode conversion will be performed.
        /// 0x00000002 - Perform on-demand wipe of the volume free space. Calling the Encrypt method with this bit set is only allowed when volume is not currently converting or
        /// wiping and is in an "encrypted" state.
        /// 0x00010000 - Perform the requested operation synchronously. The call will block until requested operation has completed or was interrupted. This flag is only supported
        /// with the Encrypt method. This flag can be specified when Encrypt is called to resume stopped or interrupted encryption or wiping or when either encryption or wiping is
        /// in progress. This allows the caller to resume synchronously waiting until the process is completed or interrupted.</param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/encrypt-win32-encryptablevolume
        /// </remarks>
        public void Encrypt(EncryptionMethod encryptionMethod, uint encryptionFlags)
        {
            using (var inParams = _vol.GetMethodParameters("Encrypt"))
            {
                inParams["EncryptionMethod"] = encryptionMethod;
                inParams["EncryptionFlags"] = encryptionFlags;
                using (var outParams = _vol.InvokeMethod("Encrypt", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The EncryptionMethod parameter is provided but is not within the known range or does not match the current Group Policy setting.").SetCode(0x80070057);
                        case 0x8031002E: // FVE_E_CANNOT_ENCRYPT_NO_KEY
                            throw new InvalidOperationException("No encryption key exists for the volume. Either disable key protectors by using the DisableKeyProtectors method or use one of the"
                                                                + " following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey"
                                                                + "Windows Vista: When no encryption key exists for the volume, ERROR_INVALID_OPERATION is returned instead. The decimal value is 4317 and the hexadecimal value is 0x10DD.").SetCode(0x8031002E);
                        case 0x8031002D: // FVE_E_CANNOT_SET_FVEK_ENCRYPTED
                            throw new InvalidOperationException("The provided encryption method does not match that of the partially or fully encrypted volume.To continue encryption, leave the EncryptionMethod parameter blank"
                                                                + " or use a value of zero.").SetCode(0x8031002D);
                        case 0x8031001E: // FVE_E_CLUSTERING_NOT_SUPPORTED
                            throw new InvalidOperationException("The volume cannot be encrypted because this computer is configured to be part of a server cluster.").SetCode(0x8031001E);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x8031002C: // FVE_E_POLICY_PASSWORD_REQUIRED
                            throw new InvalidOperationException("No key protectors of the type \"Numerical Password\" are specified. The Group Policy requires a backup of recovery "
                                                                + "information to Active Directory Domain Services. To add at least one key protector of that type, use the ProtectKeyWithNumericalPassword method.").SetCode(0x8031002C);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Begins encryption of a fully decrypted operating system volume after a hardware test. A reboot is required to perform this hardware test.
        /// Use this method instead of the Encrypt method to check that BitLocker will work as expected.
        /// </summary>
        /// <param name="encryptionMethod">
        /// Specifies the encryption algorithm and key size used to encrypt the volume. Leave this parameter blank to use the default value of zero. If the volume is
        /// partially or fully encrypted, the value of this parameter must be 0 or match the volume's existing encryption method. If the corresponding Group Policy
        /// setting has been enabled with a valid value, the value of this parameter must be 0 or match the Group Policy setting.
        /// If the corresponding Group Policy setting is invalid, the default of AES 128 with diffuser is used.</param>
        /// <param name="encryptionFlags">
        /// Flags that describe the encryption behavior.
        /// Windows 7, Windows Server 2008 R2, Windows Vista Enterprise and Windows Server 2008: This parameter is not available.
        /// A combination of 32 bits with the following bits currently defined.
        /// 0x00000001: 
        /// Perform volume encryption in data-only encryption mode when starting new encryption process. If encryption has been paused or stopped,
        /// calling the Encrypt method effectively resumes conversion and the value of this bit is ignored. This bit only has effect when either
        /// the Encrypt or EncryptAfterHardwareTest methods start encryption from the fully decrypted state, decryption in progress state, or
        /// decryption paused state. If this bit is zero, meaning that it is not set, when starting new encryption process, then full mode conversion will be performed.
        /// 0x00000002: 
        /// Perform on-demand wipe of the volume free space. Calling the Encrypt method with this bit set is only allowed when volume is not
        /// currently converting or wiping and is in an "encrypted" state.
        /// 0x00010000: 
        /// Perform the requested operation synchronously. The call will block until requested operation has completed or was interrupted.
        /// This flag is only supported with the Encrypt method. This flag can be specified when Encrypt is called to resume stopped or
        /// interrupted encryption or wiping or when either encryption or wiping is in progress. This allows the caller to resume
        /// synchronously waiting until the process is completed or interrupted.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
        /// </remarks>
        public void EncryptAfterHardwareTest(EncryptionMethod encryptionMethod, uint encryptionFlags)
        {
            using (var inParams = _vol.GetMethodParameters("EncryptAfterHardwareTest"))
            {
                inParams["EncryptionMethod"] = encryptionMethod;
                inParams["EncryptionFlags"] = encryptionFlags;
                using (var outParams = _vol.InvokeMethod("EncryptAfterHardwareTest", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The EncryptionMethod parameter is provided but is not within the known range or does not match the current Group Policy setting.").SetCode(0x80070057);
                        case 0x8031002E: // FVE_E_CANNOT_ENCRYPT_NO_KEY
                            throw new InvalidOperationException("No encryption key exists for the volume. Either disable key protectors by using the DisableKeyProtectors method or use one of the"
                                                                + " following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey"
                                                                + "Windows Vista: When no encryption key exists for the volume, ERROR_INVALID_OPERATION is returned instead. The decimal value is 4317 and the hexadecimal value is 0x10DD.").SetCode(0x8031002E);
                        case 0x8031001E: // FVE_E_CLUSTERING_NOT_SUPPORTED
                            throw new InvalidOperationException("The volume cannot be encrypted because this computer is configured to be part of a server cluster.").SetCode(0x8031001E);

                        case 0x8031003B: // FVE_E_NO_PROTECTORS_TO_TEST
                            throw new InvalidOperationException("No key protectors of the type \"TPM\", \"TPM And PIN\", \"TPM And PIN And Startup Key\", \"TPM And Startup Key\", or \"External Key\" "
                                                                + "can be found.The hardware test only involves the previous key protectors. If you still want to run a hardware test, you must use one of "
                                                                + "the following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey").SetCode(0x8031003B);
                        case 0x80310039: // FVE_E_NOT_DECRYPTED
                            throw new InvalidOperationException("The volume is partially or fully encrypted. The hardware test applies before encryption occurs. If you still want to run the test,"
                                                                + " first use the Decrypt method and then use one of the following methods to add key protectors: ProtectKeyWithExternalKey,"
                                                                + " ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndStartupKey.").SetCode(0x80310039);
                        case 0x80310028: // FVE_E_NOT_OS_VOLUME
                            throw new InvalidOperationException("The volume is a data volume. The hardware test applies only to volumes that can start the operating system. Run this method on the "
                                                                + "currently started operating system volume.").SetCode(0x80310028);
                        case 0x8031002C: // FVE_E_POLICY_PASSWORD_REQUIRED
                            throw new InvalidOperationException("No key protectors of the type \"Numerical Password\" are specified. The Group Policy requires a backup of recovery "
                                                                + "information to Active Directory Domain Services. To add at least one key protector of that type, use the ProtectKeyWithNumericalPassword method.").SetCode(0x8031002C);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Enumerates all certificates on the system that match the indicated criteria and returns a list of thumbprints. The returned list only contains certificates with a
        /// valid object identifier (OID). The OID may be the default, or it may be specified in the Group Policy.
        /// </summary>
        /// <param name="certificateThumbprint">
        /// An array of strings that contains the list of valid certificates.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/findvalidcertificates-win32-encryptablevolume
        /// </remarks>
        public void FindValidCertificates(out string[] certificateThumbprint)
        {
            using (var inParams = _vol.GetMethodParameters("FindValidCertificates"))
            {
                using (var outParams = _vol.InvokeMethod("FindValidCertificates", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    certificateThumbprint = (string[])outParams["CertificateThumbprint"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x8031006E: // FVE_E_INVALID_BITLOCKER_OID
                            throw new InvalidOperationException("The available BitLocker OID is not valid.").SetCode(0x8031006E);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates the status of the encryption or decryption on the volume.
        /// </summary>
        /// <param name="conversionStatus">
        /// Volume encryption or decryption status.
        /// </param>
        /// <param name="encryptionPercentage">
        /// Percentage of the volume that is encrypted. This is an integer from 0 to 100 inclusive.
        /// Due to rounding of numbers, an encryption percentage of 0 or 100 does not necessarily indicate that the disk is fully decrypted or
        /// fully encrypted. Always use ConversionStatus to determine whether the disk is in fact fully decrypted or fully encrypted.</param>
        /// <param name="encryptionFlags">
        /// Flags that describe the encryption behavior.
        /// A combination of 32 bits with following bits currently defined.
        /// 0x00000001: Perform volume encryption in data-only encryption mode when starting new encryption process. If encryption has been paused
        /// or stopped, calling the Encrypt method effectively resumes conversion and the value of this bit is ignored. This bit only has effect
        /// when either the Encrypt or EncryptAfterHardwareTest methods start encryption from the fully decrypted state, decryption in progress state,
        /// or decryption paused state. If this bit is zero, meaning that it is not set, when starting new encryption process, then full mode conversion will be performed.
        /// 0x00000002: Perform on-demand wipe of the volume free space. Calling the Encrypt method with this bit set is only allowed when volume is not currently converting
        /// or wiping and is in an "encrypted" state.
        /// 0x00010000: Perform the requested operation synchronously. The call will block until requested operation has completed or was interrupted. This flag is
        /// only supported with the Encrypt method. This flag can be specified when Encrypt is called to resume stopped or interrupted encryption or wiping or when
        /// either encryption or wiping is in progress. This allows the caller to resume synchronously waiting until the process is completed or interrupted.
        /// </param>
        /// <param name="wipingStatus">
        /// Free space wiping status.
        /// </param>
        /// <param name="wipingPercentage">
        /// A value from 0 to 100 that specifies the percentage of free space that has been wiped.
        /// </param>
        /// <param name="precisionFactor">
        /// A value from 0 to 4 that specifies the precision level
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
        /// </remarks>
        public void GetConversionStatus(
            out ConversionStatus conversionStatus,
            out uint encryptionPercentage,
            out uint encryptionFlags,
            out WipingStatus wipingStatus,
            out uint wipingPercentage,
            uint precisionFactor)
        {
            conversionStatus = 0;
            encryptionPercentage = 0;
            encryptionFlags = 0;
            wipingStatus = 0;
            wipingPercentage = 0;

            using (var inParams = _vol.GetMethodParameters("GetConversionStatus"))
            {
                inParams["PrecisionFactor"] = precisionFactor;
                using (var outParams = _vol.InvokeMethod("GetConversionStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    conversionStatus = (ConversionStatus)outParams["ConversionStatus"];
                    encryptionPercentage = (uint)outParams["EncryptionPercentage"];
                    encryptionFlags = (uint)outParams["EncryptionFlags"];
                    wipingStatus = (WipingStatus)outParams["WipingStatus"];
                    wipingPercentage = (uint)outParams["WipingPercentage"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates the encryption algorithm and key size used on the volume.
        /// </summary>
        /// <param name="encryptionMethod">
        /// An unsigned integer that specifies the encryption algorithm and key size used on the volume.
        /// </param>
        /// <param name="selfEncryptionDriveEncryptionMethod">
        /// The encryption algorithm is configured on the self-encrypting drive. A null string means that either BitLocker is using software encryption or no encryption method is reported.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume
        /// </remarks>
        public void GetEncryptionMethod(out EncryptionMethod encryptionMethod, out string selfEncryptionDriveEncryptionMethod)
        {
            using (var inParams = _vol.GetMethodParameters("GetEncryptionMethod"))
            {
                using (var outParams = _vol.InvokeMethod("GetEncryptionMethod", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];

                    encryptionMethod = (EncryptionMethod)outParams["EncryptionMethod"];
                    selfEncryptionDriveEncryptionMethod = (string)outParams["SelfEncryptionDriveEncryptionMethod"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Returns the name of the file that contains the external key, if this external key is saved to a file location by using the SaveExternalKeyToFile method.
        /// This method is only applicable for key protectors of the type "External Key", "TPM And PIN And Startup Key", or "TPM And Startup Key".
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="filename">
        /// A string that specifies the name with extension but without the file path, of the file that contains the external key.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getexternalkeyfilename-win32-encryptablevolume
        /// </remarks>
        public void GetExternalKeyFileName(string volumeKeyProtectorId, out string filename)
        {
            using (var inParams = _vol.GetMethodParameters("GetExternalKeyFileName"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetExternalKeyFileName", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    filename = (string)outParams["FileName"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"External Key\", "
                                                                + "\"TPM And PIN And Startup Key\", or \"TPM And Startup Key\".").SetCode(0x80070057);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Returns the external key from a file created by SaveExternalKeyToFile, given the location of that file.
        /// </summary>
        /// <param name="pathWithFileName">
        /// A string that specifies the location of the file containing an external key.
        /// </param>
        /// <param name="externalKey">
        /// An array of bytes that is the 256-bit external key contained within the file that can be used to unlock a volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getexternalkeyfromfile-win32-encryptablevolume
        /// </remarks>
        public void GetExternalKeyFromFile(string pathWithFileName, out byte[] externalKey)
        {
            using (var inParams = _vol.GetMethodParameters("GetExternalKeyFromFile"))
            {
                inParams["PathWithFileName"] = pathWithFileName;
                using (var outParams = _vol.InvokeMethod("GetExternalKeyFromFile", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    externalKey = (byte[])outParams["ExternalKey"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException(
                                "The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"External Key\", "
                                + "\"TPM And PIN And Startup Key\", or \"TPM And Startup Key\".").SetCode(0x80070057);
                        case 0x80070002: // ERROR_FILE_NOT_FOUND
                            throw new InvalidOperationException("Cannot find file at the location specified.").SetCode(0x80070002);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether the volume is located on a drive that supports or can support hardware encryption.
        /// </summary>
        /// <param name="hardwareEncryptionStatus">
        /// Specifies whether the drive can support hardware encryption. This can be one of the following values.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/gethardwareencryptionstatus-win32-encryptablevolume
        /// </remarks>
        public void GetHardwareEncryptionStatus(out HardwareEncryptionStatus hardwareEncryptionStatus)
        {
            using (var inParams = _vol.GetMethodParameters("GetHardwareEncryptionStatus"))
            {
                using (var outParams = _vol.InvokeMethod("GetHardwareEncryptionStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    hardwareEncryptionStatus = (HardwareEncryptionStatus)outParams["HardwareEncryptionStatus"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Provides status information about a hardware test of a fully decrypted operating system volume.
        /// Use this method to show whether a hardware test is pending, as well as the success or failure of a hardware test that completed
        /// on the last computer restart. To request a hardware test, use the EncryptAfterHardwareTest method.
        /// </summary>
        /// <param name="testStatus">
        /// Specifies whether a hardware test is pending, as well as the success of failure of a hardware test that completed on the last computer restart.
        /// </param>
        /// <param name="testError">
        /// Specifies the error from the last completed hardware test.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/gethardwareteststatus-win32-encryptablevolume
        /// </remarks>
        public void GetHardwareTestStatus(out TestStatus testStatus, out TestError testError)
        {
            using (var inParams = _vol.GetMethodParameters("GetHardwareTestStatus"))
            {
                using (var outParams = _vol.InvokeMethod("GetHardwareTestStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    testStatus = (TestStatus)outParams["TestStatus"];
                    testError = (TestError)outParams["TestError"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Returns the identifier string available in the volume's metadata.
        /// </summary>
        /// <param name="identificationField">
        /// A string that specifies the identification field that is assigned to the volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getidentificationfield-win32-encryptablevolume
        /// </remarks>
        public void GetIdentificationField(out string identificationField)
        {
            using (var inParams = _vol.GetMethodParameters("GetIdentificationField"))
            {
                using (var outParams = _vol.InvokeMethod("GetIdentificationField", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    identificationField = (string)outParams["IdentificationField"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("This drive is locked by BitLocker Drive Encryption.You must unlock this volume from Control Panel.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Exports information that may help salvage encrypted data when the drive is severely damaged and no data backup files exist.
        /// The exported information consists of the volume's encryption key secured by a key protector of the type "Numerical Password" or "External Key".
        /// To make use of this package, you must also save the corresponding numerical password or external key.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector. To export a key package, you must use a key protector
        /// of type "Numerical Password" or "External Key".
        /// </param>
        /// <param name="keyPackage">
        /// A byte stream that contains the encryption key for a volume, secured by the specified key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeypackage-win32-encryptablevolume
        /// </remarks>
        public void GetKeyPackage(string volumeKeyProtectorId, out byte[] keyPackage)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyPackage"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyPackage", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    keyPackage = (byte[])outParams["KeyPackage"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume.").SetCode(0x80310033);
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("  The VolumeKeyProtectorID parameter does not refer to a key protector of the type "
                                                                + "\"Numerical Password\" or \"External Key\".Use either the ProtectKeyWithNumericalPassword or "
                                                                + "ProtectKeyWithExternalKey method to create a key protector of the appropriate type.").SetCode(0x8031003A);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }
        
        /// <summary>
        /// Retrieves the security identifier and flags used to protect a key.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A string identifier that can be used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="sidString">
        /// A string that contains the security identifier (SID).
        /// </param>
        /// <param name="flags">
        /// Flags that change the function behavior. 
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectoradsidinformation-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorAdSidInformation(string volumeKeyProtectorId, out string sidString, out KeyProtectorFlag flags)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorAdSidInformation"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorAdSidInformation", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    sidString = (string)outParams["SidString"];
                    flags = (KeyProtectorFlag)outParams["Flags"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the public key and certificate thumbprint for a public key protector.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="publicKey">
        /// An array of bytes that specifies the public key.
        /// </param>
        /// <param name="certThumbprint">
        /// A string that specifies the certificate thumbprint.
        /// </param>
        /// <param name="certType">
        /// An unsigned integer that specifies the type of the key protector. This integer is used to differentiate between data recovery agent (DRA) and user certificates.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectorcertificate-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorCertificate(string volumeKeyProtectorId, out byte[] publicKey, out string certThumbprint, out CertificateType certType)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorCertificate"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorCertificate", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    publicKey = (byte[])outParams["PublicKey"];
                    certThumbprint = (string)outParams["CertThumbprint"];
                    certType = (CertificateType)outParams["CertType"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The specified key protector is not a key protector. You must enter another key protector.").SetCode(0x80070057);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("This drive is locked by BitLocker Drive Encryption.You must unlock this volume from Control Panel.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException(" BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310073: // FVE_E_POLICY_USER_CERTIFICATE_REQUIRED
                            throw new InvalidOperationException("Group Policy requires the use of a user certificate, such as a smart card.").SetCode(0x80310073);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the external key for a given key protector of the appropriate type.
        /// The key protector identifier must refer to a key protector of type "External Key", "TPM And PIN And Startup Key", or "TPM And Startup Key".
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="externalKey">
        /// An array of bytes that specifies the 256-bit external key that can be used to unlock the corresponding volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectorexternalkey-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorExternalKey(string volumeKeyProtectorId, out byte[] externalKey)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorExternalKey"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorExternalKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    externalKey = (byte[])outParams["ExternalKey"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"External Key\","
                                                                + " \"TPM And PIN And Startup Key\", or \"TPM And Startup Key\".").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the display name used to identify a given key protector.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="friendlyName">
        /// A string that contains the user-specified name used to identify the given key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectorfriendlyname-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorFriendlyName(string volumeKeyProtectorId, out string friendlyName)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorFriendlyName"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorFriendlyName", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    friendlyName = (string)outParams["FriendlyName"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid key protector.").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the numerical password for a given key protector of the appropriate type.
        /// The key protector identifier must refer to a key protector of type "Numerical Password".
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="numericalPassword">
        /// A string that represents the password that can be used to unlock the corresponding volume.
        /// The numerical password is 48 digits. These digits are divided into 8 groups of 6 digits, with the last digit in each group indicating a
        /// checksum value for the group. Assuming that a group of six digits is labeled as x1, x2, x3, x4, x5, and x6, the checksum x6 digit is calculated as –x1+x2–x3+x4–x5 mod 11.
        /// The groups of digits are separated by a hyphen. Therefore, "xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx" is the format of the returned password.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectornumericalpassword-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorNumericalPassword(string volumeKeyProtectorId, out string numericalPassword)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorNumericalPassword"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorNumericalPassword", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    numericalPassword = (string)outParams["NumericalPassword"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"Numerical Password\".").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the platform validation profile for a given key protector of the appropriate type.
        /// The key protector identifier must refer to a key protector of type "TPM", "TPM And PIN", "TPM And PIN And Startup Key", or "TPM And Startup Key".
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="platformValidationProfile">
        /// An array of integers that specifies how the Trusted Platform Module (TPM) Security Hardware of the computer secures the encryption key of the disk volume.
        /// Value - Meaning:
        /// 0 - Core Root of Trust of Measurement(CRTM), BIOS, and Platform Extensions.
        /// 1 - Platform and Motherboard Configuration and Data.
        /// 2 - Option ROM Code.
        /// 3 - Option ROM Configuration and Data.
        /// 4 - Master Boot Record(MBR) Code.
        /// 5 - Master Boot Record(MBR) Partition Table.
        /// 6 - State Transition and Wake Events.
        /// 7 - Computer Manufacturer-Specific.
        /// 8 - NTFS Boot Sector.
        /// 9 - NTFS Boot Block.
        /// 10 - Boot Manager.
        /// 11 - BitLocker Access Control.
        /// 12 - Defined for use by the static operating system.
        /// 13 - Defined for use by the static operating system.
        /// 14 - Defined for use by the static operating system.
        /// 15 - Defined for use by the static operating system.
        /// 16 - Used for debugging.
        /// 17 - Dynamic CRTM.
        /// 18 - Platform defined.
        /// 19 - Used by a trusted operating system.
        /// 20 - Used by a trusted operating system.
        /// 21 - Used by a trusted operating system.
        /// 22 - Used by a trusted operating system.
        /// 23 - Application support.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectorplatformvalidationprofile-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorPlatformValidationProfile(string volumeKeyProtectorId, out byte[] platformValidationProfile)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorPlatformValidationProfile"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorPlatformValidationProfile", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    platformValidationProfile = (byte[])outParams["PlatformValidationProfile"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException(
                                "The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"TPM\", \"TPM And PIN\","
                                + " \"TPM And PIN And Startup Key\", or \"TPM And Startup Key\".").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException(
                                "BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Lists the protectors used to secure the volume's encryption key. If a protector type is provided,
        /// then only volume key protectors of the specified type are returned.
        /// </summary>
        /// <param name="keyProtectorType">
        /// An unsigned integer that specifies the type of key protector to return.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// An array of strings that identify the key protectors used to secure the volume's encryption key.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectors(KeyProtectorType keyProtectorType, out string[] volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectors"))
            {
                inParams["KeyProtectorType"] = (uint)keyProtectorType;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectors", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string[])outParams["VolumeKeyProtectorID"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter is specified but does not refer to a valid KeyProtectorType.").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED 
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates the type of a given key protector.
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="keyProtectorType">
        /// Type of the key protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectortype-win32-encryptablevolume
        /// </remarks>
        public void GetKeyProtectorType(string volumeKeyProtectorId, out KeyProtectorType keyProtectorType)
        {
            using (var inParams = _vol.GetMethodParameters("GetKeyProtectorType"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                using (var outParams = _vol.InvokeMethod("GetKeyProtectorType", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    keyProtectorType = (KeyProtectorType)outParams["KeyProtectorType"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid KeyProtectorType.").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether the contents of the volume are accessible from Windows.
        /// </summary>
        /// <param name="lockStatus">
        /// Specifies whether the contents of the volume are accessible from Windows.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getlockstatus-win32-encryptablevolume
        /// </remarks>
        public void GetLockStatus(out LockStatus lockStatus)
        {
            using (var inParams = _vol.GetMethodParameters("GetLockStatus"))
            {
                using (var outParams = _vol.InvokeMethod("GetLockStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    lockStatus = (LockStatus)outParams["LockStatus"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether the volume and its encryption key (if any) are secured.
        /// Protection is off if a volume is unencrypted or partially encrypted, or if the volume's encryption key is available in the clear on the hard disk.
        /// </summary>
        /// <param name="protectionStatus">
        /// Specifies whether the volume and the encryption key (if any) are secured.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume
        /// </remarks>
        public void GetProtectionStatus(out ProtectionStatus protectionStatus)
        {
            using (var inParams = _vol.GetMethodParameters("GetProtectionStatus"))
            {
                using (var outParams = _vol.InvokeMethod("GetProtectionStatus", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    protectionStatus = (ProtectionStatus)outParams["ProtectionStatus"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the number of reboots before protection will automatically be resumed.
        /// </summary>
        /// <param name="suspendCount">
        /// An integer value from 0 to 15.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getsuspendcount-win32-encryptablevolume
        /// </remarks>
        public void GetSuspendCount(out uint suspendCount)
        {
            using (var inParams = _vol.GetMethodParameters("GetSuspendCount"))
            {
                using (var outParams = _vol.InvokeMethod("GetSuspendCount", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    suspendCount = (uint)outParams["SuspendCount"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070032: // ERROR_NOT_SUPPORTED
                            throw new InvalidOperationException("Returned if the volume is not suspended or is not an OS volume.").SetCode(0x80070032);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Returns the FVE metadata version of the volume.
        /// </summary>
        /// <param name="version">
        /// Metadata version of the volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/getversion-win32-encryptablevolume
        /// </remarks>
        public void GetVersion(out FVEMetadataVersion version)
        {
            using (var inParams = _vol.GetMethodParameters("GetVersion"))
            {
                using (var outParams = _vol.InvokeMethod("GetVersion", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    version = (FVEMetadataVersion)outParams["Version"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0xCCD802F: // E_INVALIDARG
                            throw new InvalidOperationException("The value for the Version parameter is not valid.").SetCode(0xCCD802F);
                        case 0xD: // ERROR_INVALID_DATA
                            throw new InvalidOperationException("The driver returned an unsupported data format.").SetCode(0xD);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether the volume is automatically unlocked when it is mounted (for example, when removable memory devices are connected to the computer).
        /// </summary>
        /// <param name="isAutoUnlockEnabled">
        /// A Boolean value that is true if the external key used to automatically unlock the volume exists and has been stored in the currently
        /// running operating system volume, otherwise it is false.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier that contains the associated encrypted volume key protector ID if IsAutoUnlockEnabled is true.
        /// If IsAutoUnlockEnabled is false, VolumeKeyProtectorID is an empty string.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/isautounlockenabled-win32-encryptablevolume
        /// </remarks>
        public void IsAutoUnlockEnabled(out bool isAutoUnlockEnabled, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("IsAutoUnlockEnabled"))
            {
                using (var outParams = _vol.InvokeMethod("IsAutoUnlockEnabled", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    isAutoUnlockEnabled = (bool)outParams["IsAutoUnlockEnabled"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310019: // FVE_E_NOT_DATA_VOLUME
                            throw new InvalidOperationException("The method cannot be run for the currently running operating system volume.").SetCode(0x80310019);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether any external keys or related information that may be used to automatically unlock data volumes exist in the currently running operating system volume.
        /// </summary>
        /// <param name="isAutoUnlockKeyStored">
        /// Is true if any information that can be used to automatically unlock data volumes is stored in the registry of the currently running operating system volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/isautounlockkeystored-win32-encryptablevolume
        /// </remarks>
        public void IsAutoUnlockKeyStored(out bool isAutoUnlockKeyStored)
        {
            using (var inParams = _vol.GetMethodParameters("IsAutoUnlockKeyStored"))
            {
                using (var outParams = _vol.InvokeMethod("IsAutoUnlockKeyStored", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    isAutoUnlockKeyStored = (bool)outParams["IsAutoUnlockKeyStored"];
                    
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310028: // FVE_E_NOT_OS_VOLUME
                            throw new InvalidOperationException("The method can only be run for the currently running operating system volume.").SetCode(0x80310028);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether protectors are available for the volume.
        /// If a protector type is provided, then the method indicates whether protectors of the specified type are available for the volume.
        /// </summary>
        /// <param name="keyProtectorType">
        /// An unsigned integer that indicates the type of volume key protector queried.
        /// </param>
        /// <param name="isKeyProtectorAvailable">
        /// A Boolean value that indicates whether a volume key protector of the specified type exists on the volume.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/iskeyprotectoravailable-win32-encryptablevolume
        /// </remarks>
        public void IsKeyProtectorAvailable(KeyProtectorType keyProtectorType, out bool isKeyProtectorAvailable)
        {
            using (var inParams = _vol.GetMethodParameters("IsKeyProtectorAvailable"))
            {
                inParams["KeyProtectorType"] = (uint)keyProtectorType;
                using (var outParams = _vol.InvokeMethod("IsKeyProtectorAvailable", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    isKeyProtectorAvailable = (bool)outParams["IsKeyProtectorAvailable"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The KeyProtectorType parameter is specified but does not refer to a valid key protector type.").SetCode(0x80070057);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether the numerical password meets the special format requirements for this authentication value.
        /// </summary>
        /// <param name="numericalPassword">
        /// A string that specifies the numerical password.
        /// The numerical password must contain 48 digits. These digits can be divided into 8 groups of 6 digits, with the last digit in each group indicating a
        /// checksum value for the group. Each group of 6 digits must be divisible by 11 and must be less than 720896. Assuming a group of six digits is labeled as
        /// x1, x2, x3, x4, x5, and x6, the checksum x6 digit is calculated as –x1+x2–x3+x4–x5 mod 11.
        /// The groups of digits can optionally be separated by a space or hyphen. Therefore,
        /// "xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx" or "xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx" may also contain valid numerical
        /// passwords.</param>
        /// <param name="isNumericalPasswordValid">
        /// A Boolean value that is true if the numerical password meets the special format requirements for this authentication value, otherwise the value is false.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/isnumericalpasswordvalid-win32-encryptablevolume
        /// </remarks>
        public void IsNumericalPasswordValid(string numericalPassword, out bool isNumericalPasswordValid)
        {
            using (var inParams = _vol.GetMethodParameters("IsNumericalPasswordValid"))
            {
                inParams["NumericalPassword"] = numericalPassword;
                using (var outParams = _vol.InvokeMethod("IsNumericalPasswordValid", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    isNumericalPasswordValid = (bool)outParams["IsNumericalPasswordValid"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Dismounts the volume and removes the volume's encryption key from system memory. The contents of the volume remain inaccessible until it is unlocked by either
        /// the UnlockWithExternalKey method or the UnlockWithNumericalPassword method. This method cannot be successfully run for the currently running operating system volume.
        /// </summary>
        /// <param name="forceDismount">
        /// If true the disk is forcibly dismounted.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/lock-win32-encryptablevolume
        /// </remarks>
        public void Lock(bool forceDismount = false)
        {
            using (var inParams = _vol.GetMethodParameters("Lock"))
            {
                inParams["ForceDismount"] = forceDismount;
                using (var outParams = _vol.InvokeMethod("Lock", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070005: // E_ACCESS_DENIED
                            throw new InvalidOperationException("Applications are accessing this volume.").SetCode(0x80070005);
                        case 0x80310001: // FVE_E_NOT_ENCRYPTED
                            throw new InvalidOperationException("The volume is fully decrypted and cannot be locked.").SetCode(0x80310001);
                        case 0x80310021: // FVE_E_PROTECTION_DISABLED
                            throw new InvalidOperationException("The volume's encryption key is available in the clear on the disk, preventing the volume from being locked.").SetCode(0x80310021);
                        case 0x80310022: // FVE_E_RECOVERY_KEY_REQUIRED
                            throw new InvalidOperationException("The volume does not have key protectors of the type \"Numerical Password\" or \"External Key\" that are necessary to unlock the volume.").SetCode(0x80310022);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Pauses the encryption or decryption of a volume.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/pauseconversion-win32-encryptablevolume
        /// </remarks>
        public void PauseConversion()
        {
            using (var inParams = _vol.GetMethodParameters("PauseConversion"))
            {
                using (var outParams = _vol.InvokeMethod("PauseConversion", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Creates a BitLocker volume with the specified file system type of the discovery volume. This method must be called before the volume
        /// can be protected with any of the ProtectKeyWith* methods.
        /// </summary>
        /// <param name="discoveryVolumeType">
        /// A string that specifies the type of discovery volume.
        /// Value - Meaning.
        /// &lt;none&gt; - No discovery volume. This value creates a native BitLocker volume.
        /// &lt;default&gt; - This value is the default behavior.
        /// FAT32 - This value creates a FAT32 discovery volume.
        /// </param>
        /// <param name="forceEncryptionType">
        /// Encryption type.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/preparevolume-win32-encryptablevolume
        /// </remarks>
        public void PrepareVolume(string discoveryVolumeType, ForceEncryptionType forceEncryptionType)
        {
            using (var inParams = _vol.GetMethodParameters("PrepareVolume"))
            {
                inParams["DiscoveryVolumeType"] = discoveryVolumeType;
                inParams["ForceEncryptionType"] = (uint)forceEncryptionType;
                using (var outParams = _vol.InvokeMethod("PrepareVolume", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];

                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Secures the volume's encryption key by using a Active Directory security identifier (SID).
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="sidString">
        /// String that contains the Active Directory SID used to protect the encryption key.
        /// </param>
        /// <param name="flags">
        /// Flags that change the function behavior.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A unique identifier associated with the created protector. You can use this string to manage the key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker"
        /// and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithadsid-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithAdSid(string friendlyName, string sidString, ActiveDirectoryFlag flags, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithAdSid"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["SidString"] = sidString;
                inParams["Flags"] = (uint)flags;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithAdSid", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Validates the Enhanced Key Usage (EKU) object identifier (OID) of the provided certificate.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned string identifier for this key protector. If this parameter is not specified, the FriendlyName parameter is created by using the Subject Name in the certificate.
        /// </param>
        /// <param name="filename">
        /// A string that specifies the location and name of the .cer file used to enable BitLocker. An encryption certificate must be exported in .cer format
        /// (Distinguished Encoding Rules (DER)-encoded binary X.509 or Base-64 encoded X.509). The encryption certificate may be generated from Microsoft PKI,
        /// third-party PKI, or self-signed.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that uniquely identifies the created key protector that can be used to manage this key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithcertificatefile-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithCertificateFile(string friendlyName, string filename, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithCertificateFile"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["FileName"] = filename;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithCertificateFile", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x8031006E: // FVE_E_NON_BITLOCKER_OID
                            throw new InvalidOperationException("The EKU attribute of the specified certificate does not permit it to be used for BitLocker Drive Encryption.BitLocker does"
                                                                + " not require that a certificate have an EKU attribute, but if one is configured, it must be set to an OID that matches the"
                                                                + " OID configured for BitLocker.").SetCode(0x8031006E);
                        case 0x80310072: // FVE_E_POLICY_USER_CERTIFICATE_NOT_ALLOWED
                            throw new InvalidOperationException("Group Policy does not permit user certificates, such as smart cards, to be used with BitLocker.").SetCode(0x80310072);
                        case 0x80310074: // FVE_E_POLICY_USER_CERT_MUST_BE_HW
                            throw new InvalidOperationException("Group Policy requires that you supply a smart card to use BitLocker.").SetCode(0x80310074);
                        case 0x80310086: // FVE_E_POLICY_PROHIBITS_SELFSIGNED
                            throw new InvalidOperationException("Group Policy does not permit the use of self - signed certificates.").SetCode(0x80310086);
                        case 0x2: // ERROR_FILE_NOT_FOUND
                            throw new InvalidOperationException("The system cannot find the specified file.").SetCode(0x2);
                       default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Validates the Enhanced Key Usage (EKU) object identifier (OID) of the provided certificate.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned string identifier for this key protector. If this parameter is not specified, the FriendlyName
        /// parameter is created by using the Subject Name in the certificate.
        /// </param>
        /// <param name="certThumbprint">
        /// A string that specifies the certificate thumbprint.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that uniquely identifies the created key protector that can be used to manage this key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithcertificatethumbprint-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithCertificateThumbprint(string friendlyName, string certThumbprint, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithCertificateThumbprint"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["CertThumbprint"] = certThumbprint;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithCertificateThumbprint", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0xD: // ERROR_INVALID_DATA
                            throw new InvalidOperationException("The data is not valid.").SetCode(0xD);
                        case 0x8031006E: // FVE_E_NON_BITLOCKER_OID
                            throw new InvalidOperationException("The EKU attribute of the specified certificate does not permit it to be used for BitLocker Drive Encryption. "
                                                                + "BitLocker does not require that a certificate have an EKU attribute, but if one is configured, it must be set"
                                                                + " to an OID that matches the OID configured for BitLocker.").SetCode(0x8031006E);
                        case 0x80310072: // FVE_E_POLICY_USER_CERTIFICATE_NOT_ALLOWED
                            throw new InvalidOperationException("Group Policy does not permit user certificates, such as smart cards, to be used with BitLocker.").SetCode(0x80310072);
                        case 0x80310074: // FVE_E_POLICY_USER_CERT_MUST_BE_HW
                            throw new InvalidOperationException("Group Policy requires that you supply a smart card to use BitLocker.").SetCode(0x80310074);
                        case 0x80310086: // FVE_E_POLICY_PROHIBITS_SELFSIGNED
                            throw new InvalidOperationException("Group Policy does not permit the use of self - signed certificates.").SetCode(0x80310086);
                       default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }
        
        /// <summary>
        /// Secures the volume's encryption key with a 256-bit external key. This external key can be used to recover from the authentication failures of other key protectors (for example, TPM).
        /// Use the SaveExternalKeyToFile method to save this external key to a file. USB memory devices that contain this external key can be used as a startup key or a recovery key when the computer starts.
        /// A key protector of type "External Key" is created for the volume.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="externalKey">
        /// An array of bytes that specifies the 256-bit external key used to unlock the volume.
        /// If no external key is specified, one is randomly generated. Use the GetKeyProtectorExternalKey method to obtain the randomly generated key.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithexternalkey-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithExternalKey(string friendlyName, byte[] externalKey, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithExternalKey"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["ExternalKey"] = externalKey;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithExternalKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The ExternalKey parameter is provided but is not an array of size 4.").SetCode(0x80070057);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Secures the volume's encryption key with a specially formatted 48-digit password. This numerical password can be used to recover from the authentication
        /// failures of other key protectors (for example, TPM).
        /// A key protector of type "Numerical Password" is created for the volume.
        /// Use the IsNumericalPasswordValid method to validate the format of the numerical password.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="numericalPassword">
        /// A string that specifies the specially formatted 48-digit numerical password.
        /// The numerical password must contain 48 digits. These digits can be divided into 8 groups of 6 digits, with the last digit in each group indicating a checksum value for the group. Each group of 6 digits must be divisible by 11 and must be less than 720896. Assuming a group of six digits is labeled as x1, x2, x3, x4, x5, and x6, the checksum x6 digit is calculated as –x1+x2–x3+x4–x5 mod 11.
        /// The groups of digits can optionally be separated by a space or hyphen. Therefore, "xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx" or "xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx" may also contain valid numerical passwords.
        /// If no numerical password is specified, one is randomly generated. Use the GetKeyProtectorNumericalPassword method to obtain the randomly generated password.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that is the unique identifier associated with the created protector and that can be used to manage the key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithNumericalPassword(string friendlyName, string numericalPassword, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithNumericalPassword"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["NumericalPassword"] = numericalPassword;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithNumericalPassword", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The NumericalPassword parameter does not have a valid format.").SetCode(0x80070057);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses the passphrase to obtain the derived key. After the derived key is calculated, the derived key is used to secure the encrypted volume's master key.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned string identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="passphrase">
        /// A string that specifies the passphrase.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that uniquely identifies the created key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithPassphrase(string friendlyName, string passphrase, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithPassphrase"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["Passphrase"] = passphrase;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithPassphrase", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310040: // FVE_E_NOT_ALLOWED_IN_SAFE_MODE
                            throw new InvalidOperationException("BitLocker Drive Encryption can only be used for recovery purposes when used in Safe Mode.").SetCode(0x80310040);
                        case 0x8031006A: // FVE_E_POLICY_PASSPHRASE_NOT_ALLOWED
                            throw new InvalidOperationException("Group policy does not permit the creation of a passphrase.").SetCode(0x8031006A);
                        case 0x8031006C: // FVE_E_FIPS_PREVENTS_PASSPHRASE
                            throw new InvalidOperationException("The group policy setting that requires FIPS compliance prevented the passphrase from being generated or used.").SetCode(0x8031006C);
                        case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                            throw new InvalidOperationException("The passphrase provided does not meet the minimum or maximum length requirements.").SetCode(0x80310080);
                        case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                            throw new InvalidOperationException("The passphrase does not meet the complexity requirements set by the administrator in group policy.").SetCode(0x80310081);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is already locked by BitLocker Drive Encryption.You must unlock the drive from Control Panel.").SetCode(0x80310000);
                        case 0x80310024: // FVE_E_OVERLAPPED_UPDATE
                            throw new InvalidOperationException("The control block for the encrypted volume was updated by another thread.").SetCode(0x80310024);
                        case 0x80310069: // FVE_E_KEY_PROTECTOR_NOT_SUPPORTED
                            throw new InvalidOperationException("The key protector is not supported by the version of BitLocker Drive Encryption currently on the volume.").SetCode(0x80310069);
                        case 0x8031006D: // FVE_E_OS_VOLUME_PASSPHRASE_NOT_ALLOWED
                            throw new InvalidOperationException("The passphrase cannot be added to the operating system volume.").SetCode(0x8031006D);
                        case 0x80310030: // FVE_E_PROTECTOR_EXISTS
                            throw new InvalidOperationException("The provided key protector already exists on this volume.").SetCode(0x80310030);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }
        
        /// <summary>
        /// Secures the volume's encryption key by using the Trusted Platform Module (TPM) Security Hardware on the computer, if available.
        /// A key protector of type "TPM" is created for the volume, if one does not already exist.
        /// This method is only applicable for the volume that contains the currently running operating system, and if a key protector does not already exist on the volume.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that specifies a user-assigned string identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="platformValidationProfile">
        /// An array of integers that specifies how the computer's Trusted Platform Module (TPM) Security Hardware secures the disk volume's encryption key.
        /// Please find possible values in official documentation - https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that uniquely identifies the created protector and which can be used to manage the key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithTPM(string friendlyName, byte[] platformValidationProfile, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithTPM"))
            {
                inParams["FriendlyName"] = friendlyName;
                inParams["PlatformValidationProfile"] = platformValidationProfile;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithTPM", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible TPM is found on this computer.").SetCode(0x80284008);
                        case 0x80310023: // FVE_E_FOREIGN_VOLUME
                            throw new InvalidOperationException("The TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system.").SetCode(0x80310023);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The PlatformValidationProfile parameter is provided but its values are not within the known range,"
                                                                + " or it does not match the Group Policy setting currently in effect.").SetCode(0x80070057);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Secures the volume's encryption key by using the Trusted Platform Module (TPM) Security Hardware on the computer, if available, enhanced by a user-specified personal identification number (PIN) that must be provided to the computer at startup.
        /// Both validation by the TPM and input of the personal identification string are necessary to access the volume's encryption key and unlock volume contents.
        /// This method is only applicable for the volume that contains the currently running operating system.
        /// A key protector of type "TPM And PIN" is created for the volume, if one does not already exist.
        /// </summary>
        /// <param name="friendlyName">
        /// A user-assigned string identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="platformValidationProfile">
        /// An array of integers that specifies how the computer's Trusted Platform Module (TPM) Security Hardware secures the disk volume's encryption key.
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandpin-win32-encryptablevolume
        /// </param>
        /// <param name="pin">
        /// A user-specified personal identification string. This string must consist of a sequence of 6 to 20 digits or, if the "Allow enhanced PINs for startup"
        /// group policy is enabled, 6 to 20 letters, symbols, spaces, or numbers.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// The updated unique string identifier used to manage an encrypted volume key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and
        /// the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandpin-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithTPMAndPIN(string friendlyName, byte[] platformValidationProfile, string pin, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithTPMAndPIN"))
            {
                inParams["FriendlyName"] = friendlyName;

                if (platformValidationProfile != null)
                {
                    inParams["PlatformValidationProfile"] = platformValidationProfile;
                }

                inParams["PIN"] = pin;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithTPMAndPIN", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The PlatformValidationProfile parameter is provided, but its values are not within the known range, or "
                                                                + "it does not match the Group Policy setting currently in effect.").SetCode(0x80070057);
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.").SetCode(0x80310030);
                        case 0x80310023: // FVE_E_FOREIGN_VOLUME
                            throw new InvalidOperationException("The TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system.").SetCode(0x80310023);
                        case 0x8031009A: // FVE_E_INVALID_PIN_CHARS
                            throw new InvalidOperationException(
                                "The NewPIN parameter contains characters that are not valid.When the \"Allow enhanced PINs for startup\" Group Policy is disabled, only numbers are supported.").SetCode(0x8031009A);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310068: // FVE_E_POLICY_INVALID_PIN_LENGTH
                            throw new InvalidOperationException("The NewPIN parameter supplied is either longer than 20 characters, shorter than 6 characters, or shorter than the minimum "
                                                                + "length specified by Group Policy.").SetCode(0x80310068);
                        case 0x80310031: // FVE_E_PROTECTOR_EXISTS
                            throw new InvalidOperationException("A key protector of this type already exists.").SetCode(0x80310031);
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible TPM is found on this computer.").SetCode(0x80284008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Secures the volume's encryption key by using the Trusted Platform Module (TPM) on the computer, if available, enhanced by both a user-specified personal identification number (PIN) and by an external key that must be presented to the computer at startup.
        /// Three factors of authentication are needed to unlock the encrypted contents of the volume:
        /// Validation by the TPM
        /// Input of a 4 to 20 digit PIN or, if the "Allow enhanced PINs for startup" group policy is enabled, 4 to 20 letters, symbols, spaces, or numbers
        /// Input of a USB memory device that contains the external key
        /// Use the SaveExternalKeyToFile method to save this external key to a file on a USB memory device for usage as a startup key. This method applies only on the operating system volume. A key protector of type "TPM And PIN And Startup Key" is created.
        /// </summary>
        /// <param name="friendlyName">
        /// A string that labels this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="platformValidationProfile">
        /// An array of integers that specifies how the computer's Trusted Platform Module (TPM) Security Hardware secures the disk volume's encryption key.
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandpinandstartupkey-win32-encryptablevolume
        /// </param>
        /// <param name="pin">
        /// Contains a 4 to 20-digit personal identification number (PIN) or, if the "Allow enhanced PINs for startup" group policy is enabled, 4 and 20 letters,
        /// symbols, spaces, or numbers. This string must be provided to the computer at startup.
        /// </param>
        /// <param name="externalKey">
        /// An array of bytes that specifies the 256-bit external key used to unlock the volume when the computer starts. Leave this parameter blank to randomly
        /// generate the external key. Use the GetKeyProtectorExternalKey method to obtain the randomly generated key.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// The updated unique string identifier used to manage an encrypted volume key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandpinandstartupkey-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithTPMAndPINAndStartupKey(string friendlyName, byte[] platformValidationProfile, string pin, byte[] externalKey, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithTPMAndPINAndStartupKey"))
            {
                inParams["FriendlyName"] = friendlyName;

                if (platformValidationProfile != null)
                {
                    inParams["PlatformValidationProfile"] = platformValidationProfile;
                }

                inParams["PIN"] = pin;
                inParams["ExternalKey"] = externalKey;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithTPMAndPINAndStartupKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;

                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The PlatformValidationProfile parameter is provided, but its values are not within the known range, "
                                                                + "or it does not match the Group Policy setting that is currently in effect. The ExternalKey parameter is provided but"
                                                                + " it is not an array of size 32.").SetCode(0x80070057);
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.").SetCode(0x80310030);
                        case 0x80310023: // FVE_E_FOREIGN_VOLUME
                            throw new InvalidOperationException("The TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system.").SetCode(0x80310023);
                        case 0x8031009A: // FVE_E_INVALID_PIN_CHARS
                            throw new InvalidOperationException("The NewPIN parameter contains characters that are not valid.When the \"Allow enhanced PINs for startup\""
                                                                + " Group Policy is disabled, only numbers are supported.").SetCode(0x8031009A);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310068: // FVE_E_POLICY_INVALID_PIN_LENGTH
                            throw new InvalidOperationException("The NewPIN parameter supplied is either longer than 20 characters, shorter than 4 characters, or shorter than the "
                                                                + "minimum length specified by Group Policy.").SetCode(0x80310068);
                        case 0x80310031: // FVE_E_PROTECTOR_EXISTS
                            throw new InvalidOperationException("A key protector of this type already exists.").SetCode(0x80310031);
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible TPM is found on this computer.").SetCode(0x80284008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Secures the volume's encryption key by using the Trusted Platform Module (TPM) Security Hardware on the computer, if available, enhanced by an external
        /// key that must be presented to the computer at startup.
        /// Both validation by the TPM and input of a USB memory device that contains the external key are necessary to access the volume's encryption key and unlock
        /// the volume contents. Use the SaveExternalKeyToFile method to save this external key to a file on a USB memory device for usage as a startup key.
        /// This method is only applicable for the volume that contains the currently running operating system.
        /// A key protector of type "TPM And Startup Key" is created for the volume, if one does not already exist.
        /// </summary>
        /// <param name="friendlyName">
        /// A user-assigned string identifier for this key protector. If this parameter is not specified, a blank value is used.
        /// </param>
        /// <param name="platformValidationProfile">
        /// An array of integers that specifies how the computer's Trusted Platform Module (TPM) Security Hardware secures the encryption key of the disk volume.
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandstartupkey-win32-encryptablevolume
        /// </param>
        /// <param name="externalKey">
        /// An array of bytes that specifies the 256-bit external key used to unlock the volume when the computer starts.
        /// If no external key is specified, one is randomly generated. Use the GetKeyProtectorExternalKey method to obtain the randomly generated key.
        /// </param>
        /// <param name="volumeKeyProtectorId">
        /// A string that is the unique identifier associated with the created key protector that can be used to manage the key protector.
        /// If the drive supports hardware encryption and BitLocker has not taken band ownership, the ID string is set to "BitLocker" and the key
        /// protector is written to per band metadata.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandstartupkey-win32-encryptablevolume
        /// </remarks>
        public void ProtectKeyWithTPMAndPINAndStartupKey(string friendlyName, byte[] platformValidationProfile, byte[] externalKey, out string volumeKeyProtectorId)
        {
            using (var inParams = _vol.GetMethodParameters("ProtectKeyWithTPMAndPINAndStartupKey"))
            {
                inParams["FriendlyName"] = friendlyName;

                if (platformValidationProfile != null)
                {
                    inParams["PlatformValidationProfile"] = platformValidationProfile;
                }

                inParams["ExternalKey"] = externalKey;
                using (var outParams = _vol.InvokeMethod("ProtectKeyWithTPMAndPINAndStartupKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    volumeKeyProtectorId = (string)outParams["VolumeKeyProtectorID"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible TPM is found on this computer.").SetCode(0x80284008);
                        case 0x80310023: // FVE_E_FOREIGN_VOLUME
                            throw new InvalidOperationException("The TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system.").SetCode(0x80310023);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The PlatformValidationProfile parameter is provided, but its values are not within the known range, or it does not match"
                                                                + " the Group Policy setting currently in effect. The ExternalKey parameter is provided but is not an array of size 32.").SetCode(0x80070057);
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.").SetCode(0x80310030);
                        case 0x80310031: // FVE_E_PROTECTOR_EXISTS
                            throw new InvalidOperationException("A key protector of this type already exists.").SetCode(0x80310031);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Resumes the encryption or decryption of a volume.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/resumeconversion-win32-encryptablevolume
        /// </remarks>
        public void ResumeConversion()
        {
            using (var inParams = _vol.GetMethodParameters("ResumeConversion"))
            {
                using (var outParams = _vol.InvokeMethod("ResumeConversion", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Writes the external key associated with the specified volume key protector to a system, hidden, read-only file in the specified folder.
        /// This method is only applicable for key protectors of the type "External Key" or "TPM And Startup Key".
        /// </summary>
        /// <param name="volumeKeyProtectorId">
        /// A unique string identifier used to manage an encrypted volume key protector.
        /// </param>
        /// <param name="path">
        /// A string that contains the volume or folder location where the external key associated with the specified key protector is to be saved.
        /// This path does not include the name of the file, which is internal and may change from version to version. Use GetExternalKeyFileName to get the file name.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/saveexternalkeytofile-win32-encryptablevolume
        /// </remarks>
        public void SaveExternalKeyToFile(string volumeKeyProtectorId, string path)
        {
            using (var inParams = _vol.GetMethodParameters("SaveExternalKeyToFile"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorId;
                inParams["Path"] = path;
                using (var outParams = _vol.InvokeMethod("SaveExternalKeyToFile", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"External Key\" or \"TPM And Startup Key\".").SetCode(0x80070057);
                        case 0x80070003: // ERROR_PATH_NOT_FOUND
                            throw new InvalidOperationException("The Path parameter does not refer to a valid location. Ensure that the file name is not included in the Path parameter.").SetCode(0x80070003);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Sets the specified identifier string in the volume's metadata.
        /// </summary>
        /// <param name="identificationField">
        /// A string that specifies the identification field that is assigned to the volume. If the optional string is not present, the registry set values are used.
        /// If the string is present and not empty, the specified value is used. The IdentificationField parameter is not case-sensitive.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/setidentificationfield-win32-encryptablevolume
        /// </remarks>
        public void SetIdentificationField(string identificationField)
        {
            using (var inParams = _vol.GetMethodParameters("SetIdentificationField"))
            {
                inParams["IdentificationField"] = identificationField;
                using (var outParams = _vol.InvokeMethod("SetIdentificationField", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("This drive is locked by BitLocker Drive Encryption.You must unlock this volume from Control Panel.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses the provided Active Directory security identifier (SID) string to obtain the derived key and unlock the encrypted volume.
        /// </summary>
        /// <param name="sidString">
        /// String that contains the Active Directory SID.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithadsid-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithAdSid(string sidString)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithAdSid"))
            {
                inParams["SidString"] = sidString;
                using (var outParams = _vol.InvokeMethod("UnlockWithAdSid", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses the provided certificate file to obtain the derived key and unlock the encrypted volume.
        /// </summary>
        /// <param name="filename">
        /// A string that specifies the location and name of the .cer file used to retrieve the certificate thumbprint. An encryption certificate must be exported
        /// in .cer format (Distinguished Encoding Rules (DER)-encoded binary X.509 or Base-64 encoded X.509). The encryption certificate may be generated from
        /// Microsoft PKI, third-party PKI, or self-signed.
        /// </param>
        /// <param name="pin">
        /// A user-specified personal identification string. This string must consist of a sequence of 4 to 20 digits. This string is used to silently authenticate the key
        /// storage provider (KSP) when used with a smart card.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithcertificatefile-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithCertificateFile(string filename, string pin)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithCertificateFile"))
            {
                inParams["FileName"] = filename;
                inParams["PIN"] = pin;
                using (var outParams = _vol.InvokeMethod("UnlockWithCertificateFile", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x2: // ERROR_FILE_NOT_FOUND
                            throw new InvalidOperationException("The system cannot file the specified file.").SetCode(0x2);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                            throw new InvalidOperationException("The volume cannot be unlocked with the provided information.").SetCode(0x80310027);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.").SetCode(0x80310033);
                        case 0x80310094: // FVE_E_PRIVATEKEY_AUTH_FAILED
                            throw new InvalidOperationException("The private key, associated with the specified certificate, could not be authorized.The private key "
                                                                + "authorization was either not provided or the provided authorization was invalid.").SetCode(0x80310094);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses the provided certificate thumbprint to obtain the derived key and unlock the encrypted volume.
        /// </summary>
        /// <param name="certThumbprint">
        /// A thumbprint value of 0 is accepted and results in a search of the local store for the appropriate certificate.
        /// If a single BitLocker certificate is found, the search is successful. If none or more than one certificate is found, the method fails.
        /// </param>
        /// <param name="pin">
        /// A user-specified personal identification string. This string must consist of a sequence of 4 to 20 digits. This string is used to silently
        /// authenticate the key storage provider (KSP) when used with a smart card.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithcertificatethumbprint-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithCertificateThumbprint(string certThumbprint, string pin)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithCertificateThumbprint"))
            {
                inParams["CertThumbprint"] = certThumbprint;
                inParams["PIN"] = pin;
                using (var outParams = _vol.InvokeMethod("UnlockWithCertificateThumbprint", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                            throw new InvalidOperationException("The volume cannot be unlocked by using the provided information.").SetCode(0x80310027);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.").SetCode(0x80310033);
                        case 0x80310094: // FVE_E_PRIVATEKEY_AUTH_FAILED
                            throw new InvalidOperationException("The private key associated with the specified certificate could not be authorized.The private key authorization was either "
                                                                + "not provided or the provided authorization was not valid.").SetCode(0x80310094);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses a provided external key to access the contents of a data volume.
        /// The volume's encryption key must have been secured with one or more key protectors of the type "External Key" using the ProtectKeyWithExternalKey method to be able to unlock the volume with this method.
        /// </summary>
        /// <param name="externalKey">
        /// An array of bytes that specifies the 256-bit external key used to unlock the volume. This key can be obtained by calling the GetExternalKeyFromFile method.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithexternalkey-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithExternalKey(byte[] externalKey)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithExternalKey"))
            {
                inParams["ExternalKey"] = externalKey;
                using (var outParams = _vol.InvokeMethod("UnlockWithExternalKey", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x00000490: // ERROR_NOT_FOUND
                            throw new InvalidOperationException("The volume does not have a key protector of the type \"External Key\".").SetCode(0x00000490);
                        case 0x00000056: // ERROR_INVALID_PASSWORD
                            throw new InvalidOperationException("One or more key protectors of the type \"External Key\" exist, but the specified ExternalKey parameter cannot unlock the volume.").SetCode(0x00000056);
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The ExternalKey parameter is not an array of size 4.").SetCode(0x80070057);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses a provided numerical password to access the contents of a data volume.
        /// The volume's encryption key must have been secured with one or more key protectors of the type "Numerical Password" (by using the ProtectKeyWithNumericalPassword method) to be able
        /// to unlock the volume with this method.
        /// </summary>
        /// <param name="numericalPassword">
        /// A string that specifies the numerical password.
        /// The numerical password must contain 48 digits. These digits can be divided into 8 groups of 6 digits, with the last digit in each group indicating a checksum value for the group.
        /// Each group of 6 digits must be divisible by 11 and must be less than 65536. Assuming a group of six digits is labeled as x1, x2, x3, x4, x5, and x6, the checksum x6 digit is
        /// calculated as –x1+x2–x3+x4–x5 mod 11.
        /// The groups of digits can optionally be separated by a space or hyphen. Therefore, "xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx" or "xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx"
        /// may also contain valid numerical passwords.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithnumericalpassword-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithNumericalPassword(string numericalPassword)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithNumericalPassword"))
            {
                inParams["NumericalPassword"] = numericalPassword;
                using (var outParams = _vol.InvokeMethod("UnlockWithNumericalPassword", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The volume does not have a key protector of the type \"Numerical Password\"."
                                                                + "The NumericalPassword parameter has a valid format, but you cannot use a numerical password to unlock the volume.").SetCode(0x80310033);
                        case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                            throw new InvalidOperationException("The NumericalPassword parameter cannot unlock the volume. One or more key protectors of the type \"Numerical Password\" exist,"
                                                                + " but the specified NumericalPassword parameter cannot unlock the volume.").SetCode(0x80310027);
                        case 0x80310035: // FVE_E_INVALID_PASSWORD_FORMAT
                            throw new InvalidOperationException("The NumericalPassword parameter does not have a valid format.").SetCode(0x80310035);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Uses the passphrase to obtain the derived key. After the derived key is calculated, the derived key is used to unlock the encrypted volume's master key.
        /// </summary>
        /// <param name="passphrase">
        /// A string that specifies the passphrase.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/unlockwithpassphrase-win32-encryptablevolume
        /// </remarks>
        public void UnlockWithPassphrase(string passphrase)
        {
            using (var inParams = _vol.GetMethodParameters("UnlockWithPassphrase"))
            {
                inParams["Passphrase"] = passphrase;
                using (var outParams = _vol.InvokeMethod("UnlockWithPassphrase", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        case 0x8031006C: // FVE_E_FIPS_PREVENTS_PASSPHRASE
                            throw new InvalidOperationException("The group policy setting that requires FIPS compliance prevented the passphrase from being generated or used.").SetCode(0x8031006C);
                        case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                            throw new InvalidOperationException("The passphrase provided does not meet the minimum or maximum length requirements.").SetCode(0x80310080);
                        case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                            throw new InvalidOperationException("The passphrase does not meet the complexity requirements set by the administrator in group policy.").SetCode(0x80310081);
                        case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                            throw new InvalidOperationException("The volume cannot be unlocked with the provided information.").SetCode(0x80310027);
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.").SetCode(0x80310033);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Upgrades a volume from the Windows Vista format to the Windows 7 format. This is a nonreversible operation.
        /// </summary>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/upgradevolume-win32-encryptablevolume
        /// </remarks>
        public void UpgradeVolume()
        {
            using (var inParams = _vol.GetMethodParameters("UpgradeVolume"))
            {
                using (var outParams = _vol.InvokeMethod("UpgradeVolume", inParams, null))
                {
                    if (outParams == null)
                    {
                        throw new InvalidOperationException("Unable to call method. Output parameters are null.");
                    }

                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: // S_OK
                            return;
                        case 0xCCD802F: // E_INVALIDARG
                            throw new InvalidOperationException("One or more of the arguments are not valid.").SetCode(0xCCD802F);
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.").SetCode(0x80310000);
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.").SetCode(0x80310008);
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }
    }
}

#pragma warning restore CA1303 // Do not pass literals as localized parameters

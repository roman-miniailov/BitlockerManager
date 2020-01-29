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

namespace BitLockerManager
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Management;
    using System.Security.Principal;

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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            var lockStatus = (uint)outParams["LockStatus"];
                            return lockStatus == 1;
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }

        /// <summary>
        /// Lock drive.
        /// </summary>
        public void LockDrive()
        {
            var status = (uint)_vol["ProtectionStatus"];
            if (status == 1)
            {
                using (var inParams = _vol.GetMethodParameters("Lock"))
                {
                    inParams["ForceDismount"] = false;
                    using (var outParams = _vol.InvokeMethod("Lock", inParams, null))
                    {
                        var result = (uint)outParams["returnValue"];
                        switch (result)
                        {
                            case 0://S_OK
                                return;
                            case 0x80070005: // E_ACCESS_DENIED
                                throw new InvalidOperationException("Applications are accessing this volume.");
                            case 0x80310001: // FVE_E_NOT_ENCRYPTED
                                throw new InvalidOperationException("The volume is fully decrypted and cannot be locked.");
                            case 0x80310021: // FVE_E_PROTECTION_DISABLED
                                throw new InvalidOperationException("The volume's encryption key is available in the clear on the disk, preventing the volume from being locked.");
                            case 0x80310022: // FVE_E_RECOVERY_KEY_REQUIRED
                                throw new InvalidOperationException("The volume does not have key protectors of the type \"Numerical Password\" or \"External Key\" that are necessary to unlock the volume.");
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
                            var result = (uint)outParams["returnValue"];
                            switch (result)
                            {
                                case 0://S_OK
                                    return;
                                case 0x80310008: // FVE_E_NOT_ACTIVATED
                                    throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.");
                                case 0x8031006C: // FVE_E_FIPS_PREVENTS_PASSPHRASE
                                    throw new InvalidOperationException("The group policy setting that requires FIPS compliance prevented the passphrase from being generated or used.");
                                case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                                    throw new InvalidOperationException("The passphrase provided does not meet the minimum or maximum length requirements.");
                                case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                                    throw new InvalidOperationException("The passphrase does not meet the complexity requirements set by the administrator in group policy.");
                                case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                                    throw new InvalidOperationException("The volume cannot be unlocked with the provided information.");
                                case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                                    throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.");
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
                        var result = (uint)outParams["returnValue"];
                        switch (result)
                        {
                            case 0://S_OK
                                return;
                            case 0x80310008: // FVE_E_NOT_ACTIVATED
                                throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.");
                            case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                                throw new InvalidOperationException("The provided key protector does not exist on the volume. You must enter another key protector.");
                            case 0x80310027: // FVE_E_FAILED_AUTHENTICATION
                                throw new InvalidOperationException("The volume cannot be unlocked with the provided information.");
                            case 0x80310035: // FVE_E_INVALID_PASSWORD_FORMAT
                                throw new InvalidOperationException("The NumericalPassword parameter does not have a valid format.");
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
        /// <param name="volumeKeyProtectorID">
        /// Volume Key Protector ID. A unique string identifier used to manage an encrypted volume key protector.
        /// This key protector must be a numerical password protector.
        /// </param>
        /// <remarks>
        /// https://docs.microsoft.com/en-us/windows/win32/secprov/backuprecoveryinformationtoactivedirectory-win32-encryptablevolume
        /// </remarks>
        public void BackupRecoveryInformationToActiveDirectory(string volumeKeyProtectorID)
        {
            using (var inParams = _vol.GetMethodParameters("BackupRecoveryInformationToActiveDirectory"))
            {
                inParams["VolumeKeyProtectorID"] = volumeKeyProtectorID;
                using (var outParams = _vol.InvokeMethod("BackupRecoveryInformationToActiveDirectory", inParams, null))
                {
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker.");
                        case 0x1: // S_FALSE
                            throw new InvalidOperationException("Group Policy does not permit the storage of recovery information to Active Directory.");
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The specified key protector is not a numerical key protector. You must enter a numerical password protector. ");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The NewExternalKey parameter is not an array of size 32.");
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.");
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume.");
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"Numerical Password\" or "
                                                                + "\"External Key\".Use either the ProtectKeyWithNumericalPassword or ProtectKeyWithExternalKey "
                                                                + "method to create a key protector of the appropriate type.");
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
                    var result = (uint)outParams["returnValue"];
                    newProtectorId = (string)outParams["NewProtectorID"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is already locked by BitLocker Drive Encryption. You must unlock the drive from Control Panel.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80310024: // FVE_E_OVERLAPPED_UPDATE
                            throw new InvalidOperationException("The control block for the encrypted volume was updated by another thread.");
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException("The specified key protector is not of the correct type.");
                        case 0x80310080: // FVE_E_POLICY_INVALID_PASSPHRASE_LENGTH
                            throw new InvalidOperationException("The updated passphrase provided does not meet the minimum or maximum length requirements.");
                        case 0x80310081: // FVE_E_POLICY_PASSPHRASE_TOO_SIMPLE
                            throw new InvalidOperationException("The updated passphrase does not meet the complexity requirements set by the administrator in group policy.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310030: // FVE_E_BOOTABLE_CDDVD
                            throw new InvalidOperationException("A bootable CD / DVD is found in this computer.Remove the CD / DVD and restart the computer.");
                        case 0x8031009A: // FVE_E_INVALID_PIN_CHARS
                            throw new InvalidOperationException("The NewPIN parameter contains characters that are not valid.When the \"Allow enhanced PINs for startup\""
                                                                + " Group Policy is disabled, only numbers are supported.") ;
                        case 0x8031003A: // FVE_E_INVALID_PROTECTOR_TYPE
                            throw new InvalidOperationException(" The VolumeKeyProtectorID parameter does not refer to a key protector of the type \"Numerical Password\" "
                                                                + "or \"External Key\".Use either the ProtectKeyWithNumericalPassword or ProtectKeyWithExternalKey method to create a key protector of the appropriate type.");
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80310068: // FVE_E_POLICY_INVALID_PIN_LENGTH
                            throw new InvalidOperationException(" The NewPIN parameter supplied is either longer than 20 characters, shorter than 4 characters, "
                                                                + "or shorter than the minimum length specified by Group Policy.");
                        case 0x80310033: // FVE_E_PROTECTOR_NOT_FOUND
                            throw new InvalidOperationException("The provided key protector does not exist on the volume.");
                        case 0x80284008: // TBS_E_SERVICE_NOT_RUNNING
                            throw new InvalidOperationException("No compatible Trusted Platform Module(TPM) is found on this computer.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80310028: // FVE_E_NOT_OS_VOLUME
                            throw new InvalidOperationException("The method can only be run for the currently running operating system volume.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x80310029: // FVE_E_AUTOUNLOCK_ENABLED
                            throw new InvalidOperationException("This volume cannot be decrypted because keys used to automatically unlock data"
                                                                + " volumes are available. Use ClearAllAutoUnlockKeys to remove these keys.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid key protector.");
                        case 0x8031001D: // FVE_E_KEY_REQUIRED
                            throw new InvalidOperationException("The last key protector for a partially or fully encrypted volume cannot be removed if "
                                                                + "key protectors are enabled.Use DisableKeyProtectors before removing this last key protector to ensure that encrypted portions of the volume remain accessible.");
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("This key protector cannot be deleted because it is being used to automatically unlock the volume."
                                                                + " Use DisableAutoUnlock to disable automatic unlocking before deleting this key protector.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x8031001D: // FVE_E_KEY_REQUIRED
                            throw new InvalidOperationException("The last key protector for a partially or fully encrypted volume cannot be removed"
                                                                + " if key protectors are enabled.Use DisableKeyProtectors before removing this last key protector to ensure that encrypted portions"
                                                                + " of the volume remain accessible.");
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("Key protectors cannot be deleted because one of them is being used to automatically unlock the volume."
                                                                + " Use DisableAutoUnlock to disable automatic unlocking before running this method.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;

                        case 0x80310017: // FVE_E_VOLUME_NOT_BOUND
                            throw new InvalidOperationException("Automatic unlocking on the volume is disabled.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80310019: // FVE_E_NOT_DATA_VOLUME
                            throw new InvalidOperationException("The method cannot be run for the currently running operating system volume.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: //S_OK
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume.Add a key protector to enable BitLocker.");
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The VolumeKeyProtectorID parameter does not refer to a valid key protector of the type \"External Key\".");
                        case 0x80310019: // FVE_E_NOT_DATA_VOLUME
                            throw new InvalidOperationException("The method cannot be run for the currently running operating system volume.");
                        case 0x80310020: // FVE_E_OS_NOT_PROTECTED
                            throw new InvalidOperationException("The method cannot be run if the currently running operating system volume is not protected by BitLocker Drive Encryption "
                                                                + "or does not have encryption in progress.");
                        case 0x8031001F: // FVE_E_VOLUME_BOUND_ALREADY
                            throw new InvalidOperationException("Automatic unlocking on the volume has previously been enabled.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x80310007: // FVE_E_SECURE_KEY_REQUIRED
                            throw new InvalidOperationException("No key protectors exist on the volume. Use one of the following methods to specify key protectors for the volume: "
                                                                + "ProtectKeyWithCertificateFile, ProtectKeyWithCertificateThumbprint, ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword" 
                                                                + "ProtectKeyWithPassphrase, ProtectKeyWithTPM, ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey");
                        case 0x80310008: // FVE_E_NOT_ACTIVATED
                            throw new InvalidOperationException("BitLocker is not enabled on the volume. Add a key protector to enable BitLocker. ");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: //S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The EncryptionMethod parameter is provided but is not within the known range or does not match the current Group Policy setting.");
                        case 0x8031002E: // FVE_E_CANNOT_ENCRYPT_NO_KEY
                            throw new InvalidOperationException("No encryption key exists for the volume. Either disable key protectors by using the DisableKeyProtectors method or use one of the"
                                                                + " following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey" 
                                                                + "Windows Vista: When no encryption key exists for the volume, ERROR_INVALID_OPERATION is returned instead. The decimal value is 4317 and the hexadecimal value is 0x10DD.");
                        case 0x8031002D: // FVE_E_CANNOT_SET_FVEK_ENCRYPTED
                            throw new InvalidOperationException("The provided encryption method does not match that of the partially or fully encrypted volume.To continue encryption, leave the EncryptionMethod parameter blank"
                                                                + " or use a value of zero.");
                        case 0x8031001E: // FVE_E_CLUSTERING_NOT_SUPPORTED
                            throw new InvalidOperationException("The volume cannot be encrypted because this computer is configured to be part of a server cluster.");
                        case 0x80310000: // FVE_E_LOCKED_VOLUME
                            throw new InvalidOperationException("The volume is locked.");
                        case 0x8031002C: // FVE_E_POLICY_PASSWORD_REQUIRED
                            throw new InvalidOperationException("No key protectors of the type \"Numerical Password\" are specified. The Group Policy requires a backup of recovery "
                                                                + "information to Active Directory Domain Services. To add at least one key protector of that type, use the ProtectKeyWithNumericalPassword method.");
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
                    var result = (uint)outParams["returnValue"];
                    switch (result)
                    {
                        case 0: //S_OK
                            return;
                        case 0x80070057: // E_INVALIDARG
                            throw new InvalidOperationException("The EncryptionMethod parameter is provided but is not within the known range or does not match the current Group Policy setting.");
                        case 0x8031002E: // FVE_E_CANNOT_ENCRYPT_NO_KEY
                            throw new InvalidOperationException("No encryption key exists for the volume. Either disable key protectors by using the DisableKeyProtectors method or use one of the"
                                                                + " following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey"
                                                                + "Windows Vista: When no encryption key exists for the volume, ERROR_INVALID_OPERATION is returned instead. The decimal value is 4317 and the hexadecimal value is 0x10DD.");
                        case 0x8031001E: // FVE_E_CLUSTERING_NOT_SUPPORTED
                            throw new InvalidOperationException("The volume cannot be encrypted because this computer is configured to be part of a server cluster.");

                        case 0x8031003B: // FVE_E_NO_PROTECTORS_TO_TEST
                            throw new InvalidOperationException("No key protectors of the type \"TPM\", \"TPM And PIN\", \"TPM And PIN And Startup Key\", \"TPM And Startup Key\", or \"External Key\" "
                                                                + "can be found.The hardware test only involves the previous key protectors. If you still want to run a hardware test, you must use one of "
                                                                + "the following methods to specify key protectors for the volume: ProtectKeyWithExternalKey, ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, "
                                                                + "ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndPINAndStartupKey, ProtectKeyWithTPMAndStartupKey");
                        case 0x80310039: // FVE_E_NOT_DECRYPTED
                            throw new InvalidOperationException("The volume is partially or fully encrypted. The hardware test applies before encryption occurs. If you still want to run the test,"
                                                                + " first use the Decrypt method and then use one of the following methods to add key protectors: ProtectKeyWithExternalKey,"
                                                                + " ProtectKeyWithNumericalPassword, ProtectKeyWithTPM, ProtectKeyWithTPMAndPIN, ProtectKeyWithTPMAndStartupKey.");
                        case 0x80310028: // FVE_E_NOT_OS_VOLUME
                            throw new InvalidOperationException("The volume is a data volume. The hardware test applies only to volumes that can start the operating system. Run this method on the "
                                                                + "currently started operating system volume.");
                        case 0x8031002C: // FVE_E_POLICY_PASSWORD_REQUIRED
                            throw new InvalidOperationException("No key protectors of the type \"Numerical Password\" are specified. The Group Policy requires a backup of recovery "
                                                                + "information to Active Directory Domain Services. To add at least one key protector of that type, use the ProtectKeyWithNumericalPassword method.");
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
        public void FindValidCertificates(out string[] certificateThumbprint)
        {
            using (var inParams = _vol.GetMethodParameters("FindValidCertificates"))
            {
                using (var outParams = _vol.InvokeMethod("FindValidCertificates", inParams, null))
                {
                    var result = (uint)outParams["returnValue"];
                    certificateThumbprint = (string[])outParams["CertificateThumbprint"];
                    switch (result)
                    {
                        case 0://S_OK
                            return;
                        case 0x8031006E: // FVE_E_INVALID_BITLOCKER_OID
                            throw new InvalidOperationException("The available BitLocker OID is not valid.");
                        default:
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {0:X}.", result));
                    }
                }
            }
        }


    }
}

//case : // 
//throw new InvalidOperationException("");


// --------------------------------------------------------------------------------------------------------------------
// <copyright file="BitLockerManager.cs" company="Roman Minyaylov">
//   Roman Minyaylov (c) 2020.
// </copyright>
// <summary>
//   Defines the BitLockerManager type.
// </summary>
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
    }
}

//case : // 
//throw new InvalidOperationException("");


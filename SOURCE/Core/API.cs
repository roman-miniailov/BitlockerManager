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
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;

    using BitlockerManager.Enums;

    public partial class BitLockerManager
    {
        /// <summary>
        /// Is OS supported.
        /// </summary>
        /// <returns>
        /// Returns <seealso cref="bool"/>
        /// </returns>
        public static bool IsSupportedOS()
        {
            // only vista or higher
            return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                   Environment.OSVersion.Version >= new Version(6, 0);
        }

        /// <summary>
        /// Enumerate drives.
        /// </summary>
        /// <returns>
        /// Returns <seealso cref="DriveInfo"/>
        /// </returns>
        public static DriveInfo[] EnumDrives()
        {
            return DriveInfo.GetDrives();
        }

        public static bool IsLocked(DriveInfo drive)
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
            using (var wmiClass = new ManagementClass(path))
            {
                foreach (ManagementObject vol in wmiClass.GetInstances())
                {
                    var letterObj = vol["DriveLetter"];
                    if (letterObj == null)
                    {
                        continue;
                    }

                    var letter = letterObj.ToString();
                    if (drive.Name.StartsWith(letter, StringComparison.OrdinalIgnoreCase))
                    {
                        using (var inParams = vol.GetMethodParameters("GetLockStatus"))
                        {
                            using (var outParams = vol.InvokeMethod("GetLockStatus", inParams, null))
                            {
                                var result = (uint)outParams["returnValue"];
                                switch (result)
                                {
                                    case 0://S_OK
                                        var lockStatus = (uint)outParams["LockStatus"];
                                        return lockStatus == 1;
                                    default:
                                        throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Unknown code {{0:X}}.", result));
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Gets protection status.
        /// </summary>
        /// <param name="drive">
        /// The drive.
        /// </param>
        /// <returns>
        /// The <see cref="ProtectionStatus"/>.
        /// </returns>
        /// <exception cref="Exception">
        /// </exception>
        public static ProtectionStatus GetProtectionStatus(DriveInfo drive)
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
            using (var wmiClass = new ManagementClass(path))
            {
                foreach (ManagementObject vol in wmiClass.GetInstances())
                {
                    var letterObj = vol["DriveLetter"];
                    if (letterObj == null)
                    {
                        continue;
                    }

                    var letter = letterObj.ToString();

                    if (drive.Name.StartsWith(letter, StringComparison.OrdinalIgnoreCase))
                    {
                        var status = (uint)vol["ProtectionStatus"];
                        return (ProtectionStatus)status;
                    }
                }
            }

            return ProtectionStatus.Unknown;
        }

        public static bool IsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }

            return false;
        }
    }
}

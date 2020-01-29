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

namespace BitlockerManager.Enums
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Encryption algorithm and key size.
    /// </summary>
    public enum EncryptionMethod : uint
    {
        /// <summary>
        /// The volume is not encrypted.
        /// </summary>
        None = 0,

        /// <summary>
        /// The volume has been fully or partially encrypted with the Advanced Encryption Standard (AES) algorithm enhanced with a diffuser layer, using an AES key size of 128 bits.
        /// This method is no longer available on devices running Windows 8.1 or higher. 
        /// </summary>
        AES_128_WITH_DIFFUSER = 1,

        /// <summary>
        /// The volume has been fully or partially encrypted with the Advanced Encryption Standard (AES) algorithm enhanced with a diffuser layer, using an AES key
        /// size of 256 bits.This method is no longer available on devices running Windows 8.1 or higher.
        /// </summary>
        AES_256_WITH_DIFFUSER = 2,

        /// <summary>
        /// The volume has been fully or partially encrypted with the Advanced Encryption Standard (AES) algorithm, using an AES key size of 128 bits.
        /// </summary>
        AES_128 = 3,

        /// <summary>
        /// The volume has been fully or partially encrypted with the Advanced Encryption Standard(AES) algorithm, using an AES key size of 256 bits.
        /// </summary>
        AES_256 = 4,
        
        /// <summary>
        /// The volume has been fully or partially encrypted by using the hardware capabilities of the drive.
        /// </summary>
        HARDWARE_ENCRYPTION = 5,
        
        /// <summary>
        /// The volume has been fully or partially encrypted with XTS using the Advanced Encryption Standard(AES), and an AES key size of 128 bits.
        /// This method is only available on devices running Windows 10, version 1511 or higher.
        /// </summary>
        XTS_AES_128 = 6,

        /// <summary>
        /// The volume has been fully or partially encrypted with XTS using the Advanced Encryption Standard(AES), and an AES key size of 256 bits.
        /// This method is only available on devices running Windows 10, version 1511 or higher.
        /// </summary>
        XTS_AES_256 = 7,

        /// <summary>
        /// The volume has been fully or partially encrypted with an unknown algorithm and key size.
        /// </summary>
        UNKNOWN = UInt32.MaxValue - 1
    }
}

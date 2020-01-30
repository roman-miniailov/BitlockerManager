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
    /// <summary>
    /// Key protector type.
    /// </summary>
    public enum KeyProtectorType : uint
    {
        /// <summary>
        /// Unknown or other protector type.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Trusted Platform Module (TPM).
        /// </summary>
        TPM = 1,

        /// <summary>
        /// External key.
        /// </summary>
        ExternalKey = 2,

        /// <summary>
        ///  Numerical password.
        /// </summary>
        NumericalPassword = 3,

        /// <summary>
        /// TPM And PIN.
        /// </summary>
        TPMAndPIN = 4,

        /// <summary>
        /// TPM And Startup Key.
        /// </summary>
        TPMAndStartupKey = 5,

        /// <summary>
        /// TPM And PIN And Startup Key.
        /// </summary>
        TPMAndPINAndStartupKey = 6,

        /// <summary>
        /// Public Key.
        /// </summary>
        PublicKey = 7,

        /// <summary>
        /// Passphrase.
        /// </summary>
        Passphrase = 8,

        /// <summary>
        /// TPM Certificate.
        /// </summary>
        TPMCertificate = 9,

        /// <summary>
        /// CryptoAPI Next Generation (CNG) Protector.
        /// </summary>
        CNG = 10
    }
}

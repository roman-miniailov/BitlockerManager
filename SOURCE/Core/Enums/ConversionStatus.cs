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
    /// Volume encryption or decryption status.
    /// </summary>
    public enum ConversionStatus : uint
    {
        /// <summary>
        /// For a standard hard drive (HDD), the volume is fully decrypted.
        /// For a hardware encrypted hard drive (EHDD), the volume is perpetually unlocked.
        /// </summary>
        FullyDecrypted = 0,
        
        /// <summary>
        /// For a standard hard drive (HDD), the volume is fully encrypted.
        /// For a hardware encrypted hard drive (EHDD), the volume is not perpetually unlocked.
        /// </summary>
        FullyEncrypted = 1,
        
        /// <summary>
        /// The volume is partially encrypted.
        /// </summary>
        EncryptionInProgress = 2,
        
        /// <summary>
        /// The volume is partially encrypted.
        /// </summary>
        DecryptionInProgress = 3,

        /// <summary>
        /// The volume has been paused during the encryption progress. The volume is partially encrypted.
        /// </summary>
        EncryptionPaused = 4,
        
        /// <summary>
        /// The volume has been paused during the decryption progress. The volume is partially encrypted.
        /// </summary>
        DecryptionPaused = 5
    }
}

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
    /// Lock status.
    /// </summary>
    public enum LockStatus : uint
    {
        /// <summary>
        /// For a standard HDD:
        /// The full contents of the volume are accessible. An unlocked volume is either fully decrypted or has the encryption key available in
        /// the clear on disk. The volume containing the current running operating system (for example, the running Windows volume) is
        /// always accessible and cannot be locked.
        /// For an EHDD:
        /// The band is perpetually unlocked.
        /// </summary>
        Unlocked = 0,

        /// <summary>
        /// For a standard HDD:
        /// All or a portion of the contents of the volume are not accessible. A locked volume must be partially or fully encrypted and must not have
        /// the encryption key available in the clear on disk.
        /// For an EHDD:
        /// The band is unlocked or locked.
        /// </summary>
        Locked = 1
    }
}

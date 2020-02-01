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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Demo
{
    using System.IO;

    using BitLockerManager;

    using BitlockerManager.Enums;

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private DriveInfo[] _drives = null;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            _drives = BitLockerManager.EnumDrives();

            foreach (var drive in _drives)
            {
                if (BitLockerManager.GetProtectionStatus(drive) == ProtectionStatus.Protected)
                {
                    lbDrives.Items.Add(new ListBoxItem() {Content = drive.Name });
                }

                if (BitLockerManager.GetProtectionStatus(drive) == ProtectionStatus.Unknown && BitLockerManager.IsLocked(drive))
                {
                    lbDrives.Items.Add(new ListBoxItem() { Content = drive.Name });
                }
            }
        }

        private BitLockerManager GetCurrentManager()
        {
            var item = (ListBoxItem)lbDrives.SelectedItem;
            if (item.Tag != null)
            {
                return (BitLockerManager)item.Tag;
            }

            foreach (var drive in _drives)
            {
                if (drive.Name == item.Content.ToString())
                {
                    item.Tag = new BitLockerManager(drive);
                    return (BitLockerManager)item.Tag;
                }
            }

            return null;
        }

        private void UpdateSelected()
        {
            var drive = this.GetCurrentManager();
            if (drive == null)
            {
                return;
            }

            if (drive.IsLocked())
            {
                lbStatus.Text = "Status: Locked";
                btLock.IsEnabled = false;
                btUnlockPin.IsEnabled = true;
                btUnlockPassphrase.IsEnabled = true;
            }
            else
            {
                lbStatus.Text = "Status: Unlocked";
                btLock.IsEnabled = true;
                btUnlockPin.IsEnabled = false;
                btUnlockPassphrase.IsEnabled = false;
            }
        }

        private void lbDrives_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateSelected();
        }

        private void btUnlockPassphrase_Click(object sender, RoutedEventArgs e)
        {
            var drive = this.GetCurrentManager();
            if (drive == null)
            {
                return;
            }

            try
            {
                drive.UnlockDriveWithPassphrase(edPassword.Text);
                UpdateSelected();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void btUnlockPin_Click(object sender, RoutedEventArgs e)
        {
            var drive = this.GetCurrentManager();
            if (drive == null)
            {
                return;
            }

            try
            {
                drive.UnlockDriveWithNumericalPassword(edNumPassword.Text);
                UpdateSelected();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void btLock_Click(object sender, RoutedEventArgs e)
        {
            var drive = this.GetCurrentManager();
            if (drive == null)
            {
                return;
            }

            try
            {
                drive.Lock();
                UpdateSelected();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
    }
}

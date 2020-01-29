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
                drive.LockDrive();
                UpdateSelected();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
    }
}

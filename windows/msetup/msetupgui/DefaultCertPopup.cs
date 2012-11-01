using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace msetupgui
{
    public partial class DefaultCertPopup : Form
    {
        public DefaultCertPopup(IntPtr in_hkey)
        {
            InitializeComponent();
            this.hkey = in_hkey;
        }
        private IntPtr hkey;

        private void OK_Click(object sender, EventArgs e)
        {
            UInt32 result = msetupdll.MsSetDefaultCertStore(this.hkey, this.DefaultCertStoreName.Text);
            if (result != 0)
                MessageBox.Show("Set failed");
            this.Close();
        }

        private void Cancel_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}

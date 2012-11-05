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
    public partial class AddUserMapping : Form
    {
        public AddUserMapping(IntPtr in_hkey)
        {
            InitializeComponent();
            this.hkey = in_hkey;
        }

        private IntPtr hkey;

        private void OKButton_Click(object sender, EventArgs e)
        {
            UInt32 result = msetupdll.MsMapUser(hkey,
                                                this.UserName.Text,
                                                this.AccountName.Text);
            if (result != 0)
                MessageBox.Show("Add User failed");
            this.Close();
        }

        private void CancelButton_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}

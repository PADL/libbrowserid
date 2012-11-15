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
    public partial class AddServer : Form
    {
        public AddServer(IntPtr hkey)
        {
            InitializeComponent();
            this.hkey = hkey;
        }

        private IntPtr hkey;

        private void OK_Click(object sender, EventArgs e)
        {
            msetupdll.MsAddAaaServerWrapper(this.hkey, this.Address.Text, this.Port.Text, this.Secret.Text);
            this.Close();
        }

        private void Cancel_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}

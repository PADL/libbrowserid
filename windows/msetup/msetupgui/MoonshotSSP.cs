using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace msetupgui
{
    public partial class Moonshot : Form
    {
        // Why aren't these exposed anywhere in C#?
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_ACCESS_DENIED = 5;

        public Moonshot()
        {
            InitializeComponent();
            UInt32 result = msetupdll.MsOpenKey(this.server, 1, ref this.hkey);
            switch (result)
            {
            case ERROR_SUCCESS:
                SyncWithRegistry();
                break;
            case ERROR_ACCESS_DENIED:
                this.NeedsElevate = true;
                break;
            case ERROR_FILE_NOT_FOUND:
                MessageBox.Show("Moonshot not installed");
                this.Close();
                break;
            default:
                MessageBox.Show("Unexpected Error accessing registry");
                break;
            }
        }

        private void SyncWithRegistry()
        {
            UpdateFlags();
            String s = "Dummy";
            UInt32 result = msetupdll.MsGetDefaultCertStore(this.hkey, ref s);
            if (result == ERROR_SUCCESS)
                this.DefaultCertStoreName.Text = s;
            else
                this.DefaultCertStoreName.Text = "<None specified>";

            UInt32 serverIndex=0;
            ServerGrid.Rows.Clear();
            do
            {
                String[] server = new String[]{"",""};
                result = msetupdll.MsQueryAaaServer(this.hkey, serverIndex++, ref server[0], ref server[1]);
                if (result == 0)
                {
                    ServerGrid.Rows.Add(server);
                    // free strings here?
                }
            } while (result == 0);

            UInt32 userIndex = 0;
            UserMappingGrid.Rows.Clear();
            do
            {
                String[] userMapping = new String[] { "", "" };
                result = msetupdll.MsQueryUser(this.hkey,
                                               userIndex++,
                                               ref userMapping[0],
                                               ref userMapping[1]);
                if (result == 0)
                {
                    UserMappingGrid.Rows.Add(userMapping);
                    // free strings here?
                }
            } while (result == 0);
        }

        private void UpdateFlags()
        {
            UInt32 flags = 0;
            msetupdll.MsQuerySspFlags(this.hkey, ref flags);
            if ((flags & msetupdll.GSSP_FLAG_DEBUG) != 0)
                this.GSSP_Flag_Debug.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_DISABLE_SPNEGO) != 0)
                this.GSSP_Flag_Disable_SPNEGO.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_DISABLE_NEGOEX) != 0)
                this.GSSP_Flag_Disable_NegoEx.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_S4U_ON_DC) != 0)
                this.GSSP_Flag_Use_S4U_On_DC.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_FORCE_KERB_RPCID) != 0)
                this.GSSP_Flag_Force_Kerb_RPCID.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_LOGON) != 0)
                this.GSSP_Flag_Enable_Logon.Checked = true;
            if ((flags & msetupdll.GSSP_FLAG_LOGON_CREDS) != 0)
                this.GSSP_Flag_Use_Logon_Creds.Checked = true;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void GSSP_Flag_Debug_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Debug.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_DEBUG);
        }

        private void GSSP_Flag_Disable_SPNEGO_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Disable_SPNEGO.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_DISABLE_SPNEGO);
        }

        private void GSSP_Flag_Disable_NegoEx_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Disable_NegoEx.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_DISABLE_NEGOEX);
        }

        private void GSSP_Flag_Use_S4U_On_DC_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Use_S4U_On_DC.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_S4U_ON_DC);
        }

        private void GSSP_Flag_Force_Kerb_RPCID_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Force_Kerb_RPCID.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_FORCE_KERB_RPCID);
        }

        private void GSSP_Flag_Enable_Logon_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Enable_Logon.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_LOGON);
        }

        private void GSSP_Flag_Use_Logon_Creds_CheckedChanged(object sender, EventArgs e)
        {
            int fop = this.GSSP_Flag_Use_Logon_Creds.Checked ? msetupdll.SSP_FOP_ADD : msetupdll.SSP_FOP_DELETE;
            msetupdll.MsModifySspFlags(this.hkey, (UInt32)fop, msetupdll.GSSP_FLAG_LOGON_CREDS);
        }

        public Boolean NeedsElevate;
        private IntPtr hkey;
        string server;

        private void DefaultCertStoreEdit_Click(object sender, EventArgs e)
        {
            Form popup = new DefaultCertPopup(hkey);
            popup.ShowDialog();
            this.SyncWithRegistry();
        }

        private void AddUserMapping_Click(object sender, EventArgs e)
        {
            Form popup = new AddUserMapping(hkey);
            popup.ShowDialog();
            this.SyncWithRegistry();
        }
    }

    public class msetupdll
    {
        public const int SSP_FOP_SET = 0;
        public const int SSP_FOP_ADD = 1;
        public const int SSP_FOP_DELETE = 2;

        public const int GSSP_FLAG_DEBUG = 0x00000001; /* Logging on free build */
        public const int GSSP_FLAG_DISABLE_SPNEGO = 0x00000002; /* Don't register with SPNEGO */
        public const int GSSP_FLAG_DISABLE_NEGOEX = 0x00000004; /* Don't register with NegoEx */
        public const int GSSP_FLAG_S4U_ON_DC = 0x00000008; /* Use S4U2Self on DCs */
        public const int GSSP_FLAG_FORCE_KERB_RPCID = 0x00000010; /* Fake RpcID for Exchange */
        public const int GSSP_FLAG_LOGON = 0x00000020; /* Support interactive logon */
        public const int GSSP_FLAG_LOGON_CREDS = 0x00000040; /* Store domain logon credentials */
        public const int GSSP_FLAG_REG_MASK = 0x0000FFFF; /* Settable through registry */

        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsModifySspFlags(IntPtr key, UInt32 fOp, UInt32 flags);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsQuerySspFlags(IntPtr key, ref UInt32 flags);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsGetDefaultCertStore(IntPtr key, [MarshalAs(UnmanagedType.LPWStr)]ref String outString);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsSetDefaultCertStore(IntPtr key, [MarshalAs(UnmanagedType.LPWStr)]String str);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsOpenKey(string server, byte writable, ref IntPtr outKey);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsQueryAaaServer(IntPtr key, UInt32 index,
            [MarshalAs(UnmanagedType.LPWStr)]ref String outServer,
            [MarshalAs(UnmanagedType.LPWStr)]ref String outService);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsQueryUser(IntPtr key, UInt32 index,
            [MarshalAs(UnmanagedType.LPWStr)]ref String outUser,
            [MarshalAs(UnmanagedType.LPWStr)]ref String outAccount);
        [DllImport("libmsetup.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern UInt32 MsMapUser(IntPtr key,
            [MarshalAs(UnmanagedType.LPWStr)]String userName,
            [MarshalAs(UnmanagedType.LPWStr)]String accountName);
    }
}

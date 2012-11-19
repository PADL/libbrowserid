namespace msetupgui
{
    partial class Moonshot
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle1 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle2 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle3 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle4 = new System.Windows.Forms.DataGridViewCellStyle();
            this.GSSP_Flag_Debug = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Disable_SPNEGO = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Disable_NegoEx = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Use_S4U_On_DC = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Force_Kerb_RPCID = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Use_Logon_Creds = new System.Windows.Forms.CheckBox();
            this.GSSP_Flag_Enable_Logon = new System.Windows.Forms.CheckBox();
            this.DefaultCertStoreLabel = new System.Windows.Forms.Label();
            this.DefaultCertStoreName = new System.Windows.Forms.Label();
            this.DefaultCertStoreEdit = new System.Windows.Forms.Button();
            this.UserMappingLabel = new System.Windows.Forms.Label();
            this.AddUserMappingButton = new System.Windows.Forms.Button();
            this.UserMappingGrid = new System.Windows.Forms.DataGridView();
            this.User = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Account = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ServerLabel = new System.Windows.Forms.Label();
            this.AddServerButton = new System.Windows.Forms.Button();
            this.ServerGrid = new System.Windows.Forms.DataGridView();
            this.ServerAddress = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ServiceOrPort = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.RemoveUserMappingButton = new System.Windows.Forms.Button();
            this.RemoveServerButton = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.UserMappingGrid)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.ServerGrid)).BeginInit();
            this.SuspendLayout();
            // 
            // GSSP_Flag_Debug
            // 
            this.GSSP_Flag_Debug.AutoSize = true;
            this.GSSP_Flag_Debug.Location = new System.Drawing.Point(512, 30);
            this.GSSP_Flag_Debug.Name = "GSSP_Flag_Debug";
            this.GSSP_Flag_Debug.Size = new System.Drawing.Size(72, 21);
            this.GSSP_Flag_Debug.TabIndex = 0;
            this.GSSP_Flag_Debug.Text = "Debug";
            this.GSSP_Flag_Debug.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Debug.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Debug_CheckedChanged);
            // 
            // GSSP_Flag_Disable_SPNEGO
            // 
            this.GSSP_Flag_Disable_SPNEGO.AutoSize = true;
            this.GSSP_Flag_Disable_SPNEGO.Location = new System.Drawing.Point(512, 58);
            this.GSSP_Flag_Disable_SPNEGO.Name = "GSSP_Flag_Disable_SPNEGO";
            this.GSSP_Flag_Disable_SPNEGO.Size = new System.Drawing.Size(140, 21);
            this.GSSP_Flag_Disable_SPNEGO.TabIndex = 1;
            this.GSSP_Flag_Disable_SPNEGO.Text = "Disable SPNEGO";
            this.GSSP_Flag_Disable_SPNEGO.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Disable_SPNEGO.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Disable_SPNEGO_CheckedChanged);
            // 
            // GSSP_Flag_Disable_NegoEx
            // 
            this.GSSP_Flag_Disable_NegoEx.AutoSize = true;
            this.GSSP_Flag_Disable_NegoEx.Location = new System.Drawing.Point(512, 86);
            this.GSSP_Flag_Disable_NegoEx.Name = "GSSP_Flag_Disable_NegoEx";
            this.GSSP_Flag_Disable_NegoEx.Size = new System.Drawing.Size(130, 21);
            this.GSSP_Flag_Disable_NegoEx.TabIndex = 2;
            this.GSSP_Flag_Disable_NegoEx.Text = "Disable NegoEx";
            this.GSSP_Flag_Disable_NegoEx.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Disable_NegoEx.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Disable_NegoEx_CheckedChanged);
            // 
            // GSSP_Flag_Use_S4U_On_DC
            // 
            this.GSSP_Flag_Use_S4U_On_DC.AutoSize = true;
            this.GSSP_Flag_Use_S4U_On_DC.Location = new System.Drawing.Point(512, 114);
            this.GSSP_Flag_Use_S4U_On_DC.Name = "GSSP_Flag_Use_S4U_On_DC";
            this.GSSP_Flag_Use_S4U_On_DC.Size = new System.Drawing.Size(223, 21);
            this.GSSP_Flag_Use_S4U_On_DC.TabIndex = 3;
            this.GSSP_Flag_Use_S4U_On_DC.Text = "Use S4U on Domain Controller";
            this.GSSP_Flag_Use_S4U_On_DC.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Use_S4U_On_DC.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Use_S4U_On_DC_CheckedChanged);
            // 
            // GSSP_Flag_Force_Kerb_RPCID
            // 
            this.GSSP_Flag_Force_Kerb_RPCID.AutoSize = true;
            this.GSSP_Flag_Force_Kerb_RPCID.Location = new System.Drawing.Point(512, 142);
            this.GSSP_Flag_Force_Kerb_RPCID.Name = "GSSP_Flag_Force_Kerb_RPCID";
            this.GSSP_Flag_Force_Kerb_RPCID.Size = new System.Drawing.Size(166, 21);
            this.GSSP_Flag_Force_Kerb_RPCID.TabIndex = 4;
            this.GSSP_Flag_Force_Kerb_RPCID.Text = "Use Kerberos RPC ID";
            this.GSSP_Flag_Force_Kerb_RPCID.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Force_Kerb_RPCID.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Force_Kerb_RPCID_CheckedChanged);
            // 
            // GSSP_Flag_Use_Logon_Creds
            // 
            this.GSSP_Flag_Use_Logon_Creds.AutoSize = true;
            this.GSSP_Flag_Use_Logon_Creds.Location = new System.Drawing.Point(512, 196);
            this.GSSP_Flag_Use_Logon_Creds.Name = "GSSP_Flag_Use_Logon_Creds";
            this.GSSP_Flag_Use_Logon_Creds.Size = new System.Drawing.Size(226, 21);
            this.GSSP_Flag_Use_Logon_Creds.TabIndex = 5;
            this.GSSP_Flag_Use_Logon_Creds.Text = "Use Domain Logon Credentials";
            this.GSSP_Flag_Use_Logon_Creds.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Use_Logon_Creds.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Use_Logon_Creds_CheckedChanged);
            // 
            // GSSP_Flag_Enable_Logon
            // 
            this.GSSP_Flag_Enable_Logon.AutoSize = true;
            this.GSSP_Flag_Enable_Logon.Location = new System.Drawing.Point(512, 169);
            this.GSSP_Flag_Enable_Logon.Name = "GSSP_Flag_Enable_Logon";
            this.GSSP_Flag_Enable_Logon.Size = new System.Drawing.Size(193, 21);
            this.GSSP_Flag_Enable_Logon.TabIndex = 6;
            this.GSSP_Flag_Enable_Logon.Text = "Support Interactive Logon";
            this.GSSP_Flag_Enable_Logon.UseVisualStyleBackColor = true;
            this.GSSP_Flag_Enable_Logon.CheckedChanged += new System.EventHandler(this.GSSP_Flag_Enable_Logon_CheckedChanged);
            // 
            // DefaultCertStoreLabel
            // 
            this.DefaultCertStoreLabel.AutoSize = true;
            this.DefaultCertStoreLabel.Location = new System.Drawing.Point(12, 30);
            this.DefaultCertStoreLabel.Name = "DefaultCertStoreLabel";
            this.DefaultCertStoreLabel.Size = new System.Drawing.Size(121, 17);
            this.DefaultCertStoreLabel.TabIndex = 8;
            this.DefaultCertStoreLabel.Text = "Default Cert Store";
            // 
            // DefaultCertStoreName
            // 
            this.DefaultCertStoreName.AutoSize = true;
            this.DefaultCertStoreName.Location = new System.Drawing.Point(170, 30);
            this.DefaultCertStoreName.Name = "DefaultCertStoreName";
            this.DefaultCertStoreName.Size = new System.Drawing.Size(118, 17);
            this.DefaultCertStoreName.TabIndex = 9;
            this.DefaultCertStoreName.Text = "<None specified>";
            // 
            // DefaultCertStoreEdit
            // 
            this.DefaultCertStoreEdit.Location = new System.Drawing.Point(338, 30);
            this.DefaultCertStoreEdit.Name = "DefaultCertStoreEdit";
            this.DefaultCertStoreEdit.Size = new System.Drawing.Size(75, 23);
            this.DefaultCertStoreEdit.TabIndex = 10;
            this.DefaultCertStoreEdit.Text = "Edit";
            this.DefaultCertStoreEdit.UseVisualStyleBackColor = true;
            this.DefaultCertStoreEdit.Click += new System.EventHandler(this.DefaultCertStoreEdit_Click);
            // 
            // UserMappingLabel
            // 
            this.UserMappingLabel.AutoSize = true;
            this.UserMappingLabel.Location = new System.Drawing.Point(12, 62);
            this.UserMappingLabel.Name = "UserMappingLabel";
            this.UserMappingLabel.Size = new System.Drawing.Size(103, 17);
            this.UserMappingLabel.TabIndex = 11;
            this.UserMappingLabel.Text = "User Mappings";
            // 
            // AddUserMappingButton
            // 
            this.AddUserMappingButton.Location = new System.Drawing.Point(132, 62);
            this.AddUserMappingButton.Name = "AddUserMappingButton";
            this.AddUserMappingButton.Size = new System.Drawing.Size(171, 23);
            this.AddUserMappingButton.TabIndex = 12;
            this.AddUserMappingButton.Text = "Add User Mapping";
            this.AddUserMappingButton.UseVisualStyleBackColor = true;
            this.AddUserMappingButton.Click += new System.EventHandler(this.AddUserMapping_Click);
            // 
            // UserMappingGrid
            // 
            this.UserMappingGrid.AllowUserToAddRows = false;
            this.UserMappingGrid.AllowUserToDeleteRows = false;
            this.UserMappingGrid.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.UserMappingGrid.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            dataGridViewCellStyle1.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle1.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle1.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle1.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle1.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle1.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle1.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.UserMappingGrid.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle1;
            this.UserMappingGrid.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.UserMappingGrid.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.User,
            this.Account});
            dataGridViewCellStyle2.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle2.BackColor = System.Drawing.SystemColors.Window;
            dataGridViewCellStyle2.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle2.ForeColor = System.Drawing.SystemColors.ControlText;
            dataGridViewCellStyle2.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle2.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle2.WrapMode = System.Windows.Forms.DataGridViewTriState.False;
            this.UserMappingGrid.DefaultCellStyle = dataGridViewCellStyle2;
            this.UserMappingGrid.Location = new System.Drawing.Point(12, 91);
            this.UserMappingGrid.Name = "UserMappingGrid";
            this.UserMappingGrid.ReadOnly = true;
            this.UserMappingGrid.RowHeadersVisible = false;
            this.UserMappingGrid.RowTemplate.Height = 24;
            this.UserMappingGrid.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.UserMappingGrid.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.UserMappingGrid.Size = new System.Drawing.Size(480, 227);
            this.UserMappingGrid.TabIndex = 17;
            this.UserMappingGrid.CellContentClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.UserMappingGrid_CellContentClick);
            // 
            // User
            // 
            this.User.HeaderText = "User (NAI)";
            this.User.Name = "User";
            this.User.ReadOnly = true;
            // 
            // Account
            // 
            this.Account.HeaderText = "Account";
            this.Account.Name = "Account";
            this.Account.ReadOnly = true;
            // 
            // ServerLabel
            // 
            this.ServerLabel.AutoSize = true;
            this.ServerLabel.Location = new System.Drawing.Point(12, 337);
            this.ServerLabel.Name = "ServerLabel";
            this.ServerLabel.Size = new System.Drawing.Size(57, 17);
            this.ServerLabel.TabIndex = 18;
            this.ServerLabel.Text = "Servers";
            // 
            // AddServerButton
            // 
            this.AddServerButton.Location = new System.Drawing.Point(132, 331);
            this.AddServerButton.Name = "AddServerButton";
            this.AddServerButton.Size = new System.Drawing.Size(171, 23);
            this.AddServerButton.TabIndex = 19;
            this.AddServerButton.Text = "Add Server";
            this.AddServerButton.UseVisualStyleBackColor = true;
            this.AddServerButton.Click += new System.EventHandler(this.AddServerButton_Click);
            // 
            // ServerGrid
            // 
            this.ServerGrid.AllowUserToAddRows = false;
            this.ServerGrid.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            dataGridViewCellStyle3.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle3.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle3.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle3.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle3.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle3.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle3.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.ServerGrid.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle3;
            this.ServerGrid.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.ServerGrid.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.ServerAddress,
            this.ServiceOrPort});
            dataGridViewCellStyle4.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle4.BackColor = System.Drawing.SystemColors.Window;
            dataGridViewCellStyle4.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle4.ForeColor = System.Drawing.SystemColors.ControlText;
            dataGridViewCellStyle4.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle4.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle4.WrapMode = System.Windows.Forms.DataGridViewTriState.False;
            this.ServerGrid.DefaultCellStyle = dataGridViewCellStyle4;
            this.ServerGrid.Location = new System.Drawing.Point(12, 366);
            this.ServerGrid.Name = "ServerGrid";
            this.ServerGrid.RowHeadersVisible = false;
            this.ServerGrid.RowTemplate.Height = 24;
            this.ServerGrid.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.ServerGrid.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.ServerGrid.Size = new System.Drawing.Size(480, 175);
            this.ServerGrid.TabIndex = 20;
            // 
            // ServerAddress
            // 
            this.ServerAddress.HeaderText = "Server Address";
            this.ServerAddress.Name = "ServerAddress";
            this.ServerAddress.ReadOnly = true;
            // 
            // ServiceOrPort
            // 
            this.ServiceOrPort.HeaderText = "Service/Port";
            this.ServiceOrPort.Name = "ServiceOrPort";
            this.ServiceOrPort.ReadOnly = true;
            // 
            // RemoveUserMappingButton
            // 
            this.RemoveUserMappingButton.Location = new System.Drawing.Point(325, 62);
            this.RemoveUserMappingButton.Name = "RemoveUserMappingButton";
            this.RemoveUserMappingButton.Size = new System.Drawing.Size(167, 23);
            this.RemoveUserMappingButton.TabIndex = 21;
            this.RemoveUserMappingButton.Text = "Remove User Mapping";
            this.RemoveUserMappingButton.UseVisualStyleBackColor = true;
            this.RemoveUserMappingButton.Click += new System.EventHandler(this.RemoveUserMappingButton_Click);
            // 
            // RemoveServerButton
            // 
            this.RemoveServerButton.Location = new System.Drawing.Point(325, 331);
            this.RemoveServerButton.Name = "RemoveServerButton";
            this.RemoveServerButton.Size = new System.Drawing.Size(167, 23);
            this.RemoveServerButton.TabIndex = 22;
            this.RemoveServerButton.Text = "Remove Server";
            this.RemoveServerButton.UseVisualStyleBackColor = true;
            this.RemoveServerButton.Click += new System.EventHandler(this.RemoveServerButton_Click);
            // 
            // Moonshot
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(797, 575);
            this.Controls.Add(this.RemoveServerButton);
            this.Controls.Add(this.RemoveUserMappingButton);
            this.Controls.Add(this.ServerGrid);
            this.Controls.Add(this.AddServerButton);
            this.Controls.Add(this.ServerLabel);
            this.Controls.Add(this.UserMappingGrid);
            this.Controls.Add(this.AddUserMappingButton);
            this.Controls.Add(this.UserMappingLabel);
            this.Controls.Add(this.DefaultCertStoreEdit);
            this.Controls.Add(this.DefaultCertStoreName);
            this.Controls.Add(this.DefaultCertStoreLabel);
            this.Controls.Add(this.GSSP_Flag_Enable_Logon);
            this.Controls.Add(this.GSSP_Flag_Use_Logon_Creds);
            this.Controls.Add(this.GSSP_Flag_Force_Kerb_RPCID);
            this.Controls.Add(this.GSSP_Flag_Use_S4U_On_DC);
            this.Controls.Add(this.GSSP_Flag_Disable_NegoEx);
            this.Controls.Add(this.GSSP_Flag_Disable_SPNEGO);
            this.Controls.Add(this.GSSP_Flag_Debug);
            this.Name = "Moonshot";
            this.Text = "Moonshot SSP Configuration";
            this.Load += new System.EventHandler(this.Form1_Load);
            ((System.ComponentModel.ISupportInitialize)(this.UserMappingGrid)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.ServerGrid)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.CheckBox GSSP_Flag_Debug;
        private System.Windows.Forms.CheckBox GSSP_Flag_Disable_SPNEGO;
        private System.Windows.Forms.CheckBox GSSP_Flag_Disable_NegoEx;
        private System.Windows.Forms.CheckBox GSSP_Flag_Use_S4U_On_DC;
        private System.Windows.Forms.CheckBox GSSP_Flag_Force_Kerb_RPCID;
        private System.Windows.Forms.CheckBox GSSP_Flag_Use_Logon_Creds;
        private System.Windows.Forms.CheckBox GSSP_Flag_Enable_Logon;
        private System.Windows.Forms.Label DefaultCertStoreLabel;
        private System.Windows.Forms.Label DefaultCertStoreName;
        private System.Windows.Forms.Button DefaultCertStoreEdit;
        private System.Windows.Forms.Label UserMappingLabel;
        private System.Windows.Forms.Button AddUserMappingButton;
        private System.Windows.Forms.DataGridView UserMappingGrid;
        private System.Windows.Forms.Label ServerLabel;
        private System.Windows.Forms.Button AddServerButton;
        private System.Windows.Forms.DataGridView ServerGrid;
        private System.Windows.Forms.DataGridViewTextBoxColumn ServerAddress;
        private System.Windows.Forms.DataGridViewTextBoxColumn ServiceOrPort;
        private System.Windows.Forms.DataGridViewTextBoxColumn User;
        private System.Windows.Forms.DataGridViewTextBoxColumn Account;
        private System.Windows.Forms.Button RemoveUserMappingButton;
        private System.Windows.Forms.Button RemoveServerButton;
    }
}


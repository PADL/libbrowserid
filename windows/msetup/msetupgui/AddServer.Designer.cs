namespace msetupgui
{
    partial class AddServer
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
            this.AddressLabel = new System.Windows.Forms.Label();
            this.PortLabel = new System.Windows.Forms.Label();
            this.SecretLabel = new System.Windows.Forms.Label();
            this.Address = new System.Windows.Forms.TextBox();
            this.Port = new System.Windows.Forms.TextBox();
            this.Secret = new System.Windows.Forms.TextBox();
            this.OK = new System.Windows.Forms.Button();
            this.Cancel = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // AddressLabel
            // 
            this.AddressLabel.AutoSize = true;
            this.AddressLabel.Location = new System.Drawing.Point(26, 18);
            this.AddressLabel.Name = "AddressLabel";
            this.AddressLabel.Size = new System.Drawing.Size(60, 17);
            this.AddressLabel.TabIndex = 0;
            this.AddressLabel.Text = "Address";
            // 
            // PortLabel
            // 
            this.PortLabel.AutoSize = true;
            this.PortLabel.Location = new System.Drawing.Point(208, 18);
            this.PortLabel.Name = "PortLabel";
            this.PortLabel.Size = new System.Drawing.Size(85, 17);
            this.PortLabel.TabIndex = 1;
            this.PortLabel.Text = "Port/Service";
            // 
            // SecretLabel
            // 
            this.SecretLabel.AutoSize = true;
            this.SecretLabel.Location = new System.Drawing.Point(413, 18);
            this.SecretLabel.Name = "SecretLabel";
            this.SecretLabel.Size = new System.Drawing.Size(49, 17);
            this.SecretLabel.TabIndex = 2;
            this.SecretLabel.Text = "Secret";
            // 
            // Address
            // 
            this.Address.Location = new System.Drawing.Point(92, 12);
            this.Address.Name = "Address";
            this.Address.Size = new System.Drawing.Size(100, 22);
            this.Address.TabIndex = 3;
            // 
            // Port
            // 
            this.Port.Location = new System.Drawing.Point(299, 12);
            this.Port.Name = "Port";
            this.Port.Size = new System.Drawing.Size(100, 22);
            this.Port.TabIndex = 4;
            // 
            // Secret
            // 
            this.Secret.Location = new System.Drawing.Point(479, 12);
            this.Secret.Name = "Secret";
            this.Secret.Size = new System.Drawing.Size(100, 22);
            this.Secret.TabIndex = 5;
            // 
            // OK
            // 
            this.OK.Location = new System.Drawing.Point(211, 62);
            this.OK.Name = "OK";
            this.OK.Size = new System.Drawing.Size(75, 23);
            this.OK.TabIndex = 6;
            this.OK.Text = "OK";
            this.OK.UseVisualStyleBackColor = true;
            this.OK.Click += new System.EventHandler(this.OK_Click);
            // 
            // Cancel
            // 
            this.Cancel.Location = new System.Drawing.Point(341, 62);
            this.Cancel.Name = "Cancel";
            this.Cancel.Size = new System.Drawing.Size(75, 23);
            this.Cancel.TabIndex = 7;
            this.Cancel.Text = "Cancel";
            this.Cancel.UseVisualStyleBackColor = true;
            this.Cancel.Click += new System.EventHandler(this.Cancel_Click);
            // 
            // AddServer
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(624, 126);
            this.Controls.Add(this.Cancel);
            this.Controls.Add(this.OK);
            this.Controls.Add(this.Secret);
            this.Controls.Add(this.Port);
            this.Controls.Add(this.Address);
            this.Controls.Add(this.SecretLabel);
            this.Controls.Add(this.PortLabel);
            this.Controls.Add(this.AddressLabel);
            this.Name = "AddServer";
            this.Text = "Add Server";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label AddressLabel;
        private System.Windows.Forms.Label PortLabel;
        private System.Windows.Forms.Label SecretLabel;
        private System.Windows.Forms.TextBox Address;
        private System.Windows.Forms.TextBox Port;
        private System.Windows.Forms.TextBox Secret;
        private System.Windows.Forms.Button OK;
        private System.Windows.Forms.Button Cancel;
    }
}
namespace msetupgui
{
    partial class DefaultCertPopup
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
            this.CertStoreLabel = new System.Windows.Forms.Label();
            this.DefaultCertStoreName = new System.Windows.Forms.TextBox();
            this.OK = new System.Windows.Forms.Button();
            this.Cancel = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // CertStoreLabel
            // 
            this.CertStoreLabel.AutoSize = true;
            this.CertStoreLabel.Location = new System.Drawing.Point(12, 26);
            this.CertStoreLabel.Name = "CertStoreLabel";
            this.CertStoreLabel.Size = new System.Drawing.Size(121, 17);
            this.CertStoreLabel.TabIndex = 0;
            this.CertStoreLabel.Text = "Default Cert Store";
            // 
            // DefaultCertStoreName
            // 
            this.DefaultCertStoreName.Location = new System.Drawing.Point(139, 26);
            this.DefaultCertStoreName.Name = "DefaultCertStoreName";
            this.DefaultCertStoreName.Size = new System.Drawing.Size(171, 22);
            this.DefaultCertStoreName.TabIndex = 1;
            // 
            // OK
            // 
            this.OK.Location = new System.Drawing.Point(58, 77);
            this.OK.Name = "OK";
            this.OK.Size = new System.Drawing.Size(75, 23);
            this.OK.TabIndex = 2;
            this.OK.Text = "OK";
            this.OK.UseVisualStyleBackColor = true;
            this.OK.Click += new System.EventHandler(this.OK_Click);
            // 
            // Cancel
            // 
            this.Cancel.Location = new System.Drawing.Point(180, 77);
            this.Cancel.Name = "Cancel";
            this.Cancel.Size = new System.Drawing.Size(75, 23);
            this.Cancel.TabIndex = 3;
            this.Cancel.Text = "Cancel";
            this.Cancel.UseVisualStyleBackColor = true;
            this.Cancel.Click += new System.EventHandler(this.Cancel_Click);
            // 
            // DefaultCertPopup
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(322, 128);
            this.Controls.Add(this.Cancel);
            this.Controls.Add(this.OK);
            this.Controls.Add(this.DefaultCertStoreName);
            this.Controls.Add(this.CertStoreLabel);
            this.Name = "DefaultCertPopup";
            this.Text = "Default Cert Store";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label CertStoreLabel;
        private System.Windows.Forms.TextBox DefaultCertStoreName;
        private System.Windows.Forms.Button OK;
        private System.Windows.Forms.Button Cancel;
    }
}
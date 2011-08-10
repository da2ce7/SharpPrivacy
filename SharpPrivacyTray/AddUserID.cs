//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// AddUserID.cs: 
// 	This class is a GUI to add a userid to a key.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 25.05.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//  - 14.10.2003: Changes to make this dialog work with the new architecture
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	/// <summary>
	/// Summary description for AddUserID.
	/// </summary>
	public class AddUserID : System.Windows.Forms.Form {
		private System.Windows.Forms.TextBox txtEmail;
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.TextBox txtName;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.Button cmdCancel;
		private System.Windows.Forms.Button cmdAdd;
		
		private bool bIsCanceled = true;
		private XmlElement xmlPublicKey;
		private XmlElement xmlSecretKey;
		
		public bool IsCanceled {
			get {
				return bIsCanceled;
			}
		}
		
		public AddUserID() {
			//
			// Required for Windows Form Designer support
			//
			InitializeComponent();
		}
		
		public AddUserID(XmlElement xmlPublicKey, XmlElement xmlSecretKey) {
			this.xmlPublicKey = xmlPublicKey;
			this.xmlSecretKey = xmlSecretKey;
			
			InitializeComponent();
		}

		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent() {
			this.txtEmail = new System.Windows.Forms.TextBox();
			this.label3 = new System.Windows.Forms.Label();
			this.txtName = new System.Windows.Forms.TextBox();
			this.label2 = new System.Windows.Forms.Label();
			this.cmdCancel = new System.Windows.Forms.Button();
			this.cmdAdd = new System.Windows.Forms.Button();
			this.SuspendLayout();
			// 
			// txtEmail
			// 
			this.txtEmail.Font = new System.Drawing.Font("Tahoma", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.World, ((System.Byte)(0)));
			this.txtEmail.Location = new System.Drawing.Point(124, 36);
			this.txtEmail.MaxLength = 50;
			this.txtEmail.Name = "txtEmail";
			this.txtEmail.Size = new System.Drawing.Size(216, 21);
			this.txtEmail.TabIndex = 7;
			this.txtEmail.Text = "";
			// 
			// label3
			// 
			this.label3.Font = new System.Drawing.Font("Tahoma", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.World, ((System.Byte)(0)));
			this.label3.Location = new System.Drawing.Point(8, 40);
			this.label3.Name = "label3";
			this.label3.Size = new System.Drawing.Size(108, 16);
			this.label3.TabIndex = 6;
			this.label3.Text = "Your Email Address";
			// 
			// txtName
			// 
			this.txtName.Font = new System.Drawing.Font("Tahoma", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.World, ((System.Byte)(0)));
			this.txtName.Location = new System.Drawing.Point(124, 8);
			this.txtName.MaxLength = 50;
			this.txtName.Name = "txtName";
			this.txtName.Size = new System.Drawing.Size(216, 21);
			this.txtName.TabIndex = 5;
			this.txtName.Text = "";
			// 
			// label2
			// 
			this.label2.Font = new System.Drawing.Font("Tahoma", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.World, ((System.Byte)(0)));
			this.label2.Location = new System.Drawing.Point(8, 12);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(76, 16);
			this.label2.TabIndex = 4;
			this.label2.Text = "Your Name";
			// 
			// cmdCancel
			// 
			this.cmdCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.cmdCancel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdCancel.Location = new System.Drawing.Point(148, 64);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(92, 28);
			this.cmdCancel.TabIndex = 9;
			this.cmdCancel.Text = "Cancel";
			this.cmdCancel.Click += new EventHandler(this.cmdCancel_Click);
			// 
			// cmdAdd
			// 
			this.cmdAdd.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdAdd.Location = new System.Drawing.Point(248, 64);
			this.cmdAdd.Name = "cmdAdd";
			this.cmdAdd.Size = new System.Drawing.Size(92, 28);
			this.cmdAdd.TabIndex = 8;
			this.cmdAdd.Text = "Add";
			this.cmdAdd.Click += new EventHandler(this.cmdAdd_Click);
			// 
			// AddUserID
			// 
			this.AcceptButton = this.cmdAdd;
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.CancelButton = this.cmdCancel;
			this.ClientSize = new System.Drawing.Size(344, 97);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
																		  this.cmdCancel,
																		  this.cmdAdd,
																		  this.txtEmail,
																		  this.label3,
																		  this.txtName,
																		  this.label2});
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.ShowInTaskbar = false;
			this.Name = "AddUserID";
			this.Text = "Add User ID...";
			this.ResumeLayout(false);

		}
		
		private void cmdCancel_Click(object sender, EventArgs e) {
			this.Close();
		}
		
		private void cmdAdd_Click(object sender, EventArgs e) {
			if (this.txtEmail.Text.Length < 3 || this.txtName.Text.Length < 1) {
				MessageBox.Show("You must enter your full name as well as your email address!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
				return;
			}
			
			QueryPassphrase qpPassphrase = new QueryPassphrase();
			qpPassphrase.ShowSingleKeyDialog(xmlSecretKey);
			string strPassphrase = qpPassphrase.Passphrase;
			string strKeyID = xmlPublicKey.GetAttribute("keyid");
			ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
			
			try {
				SharpPrivacy.Instance.AddUserID(lKeyID, txtName.Text, txtEmail.Text, strPassphrase);
			} catch (Exception ex) {
				MessageBox.Show("Something went wrong while trying to add a new UserID: " + ex.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				return;
			}
			
			bIsCanceled = false;
			this.Close();
		}
	}

}

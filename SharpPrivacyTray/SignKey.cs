//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SignKey.cs: 
// 	This class is a GUI for signing a userid.
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
//  - 14.10.2003: Changes for new Version (with xml keys)
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Reflection;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	/// <summary>
	/// Summary description for SignKey.
	/// </summary>
	public class SignKey : System.Windows.Forms.Form {
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.TextBox txtFingerprint;
		private System.Windows.Forms.GroupBox groupBox1;
		private System.Windows.Forms.CheckBox chkExportable;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.GroupBox groupBox2;
		private System.Windows.Forms.RadioButton rbNoVerification;
		private System.Windows.Forms.RadioButton rbCasualVerification;
		private System.Windows.Forms.RadioButton rbPositivVerification;
		private System.Windows.Forms.GroupBox groupBox3;
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.TextBox txtIntroducer;
		private System.Windows.Forms.Label label4;
		private System.Windows.Forms.Button cmdSign;
		private System.Windows.Forms.Button cmdCancel;
		private System.Windows.Forms.Label label5;
		private System.Windows.Forms.ComboBox cmbUserID;
		
		private XmlElement xmlKey;
		private bool bSigned = false;
		
		public bool IsCanceled {
			get {
				return !bSigned;
			}
		}

		public SignKey(XmlElement xmlKey) {
			//
			// Required for Windows Form Designer support
			//
			InitializeComponent();
			
			this.xmlKey = xmlKey;
			XmlNodeList xnlUserIDs = xmlKey.GetElementsByTagName("UserID");
			IEnumerator ieUserIDs = xnlUserIDs.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				XmlElement xmlUserID = (XmlElement)ieUserIDs.Current;
				cmbUserID.Items.Add(xmlUserID.GetAttribute("name"));
			}
			this.txtFingerprint.Text = xmlKey.GetAttribute("keyid");
		}
		
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent() {
			this.label1 = new System.Windows.Forms.Label();
			this.txtFingerprint = new System.Windows.Forms.TextBox();
			this.groupBox1 = new System.Windows.Forms.GroupBox();
			this.label2 = new System.Windows.Forms.Label();
			this.chkExportable = new System.Windows.Forms.CheckBox();
			this.groupBox2 = new System.Windows.Forms.GroupBox();
			this.rbNoVerification = new System.Windows.Forms.RadioButton();
			this.rbCasualVerification = new System.Windows.Forms.RadioButton();
			this.rbPositivVerification = new System.Windows.Forms.RadioButton();
			this.groupBox3 = new System.Windows.Forms.GroupBox();
			this.label3 = new System.Windows.Forms.Label();
			this.txtIntroducer = new System.Windows.Forms.TextBox();
			this.label4 = new System.Windows.Forms.Label();
			this.cmdSign = new System.Windows.Forms.Button();
			this.cmdCancel = new System.Windows.Forms.Button();
			this.label5 = new System.Windows.Forms.Label();
			this.cmbUserID = new System.Windows.Forms.ComboBox();
			this.groupBox1.SuspendLayout();
			this.groupBox2.SuspendLayout();
			this.groupBox3.SuspendLayout();
			this.SuspendLayout();
			// 
			// label1
			// 
			this.label1.Location = new System.Drawing.Point(4, 8);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(244, 16);
			this.label1.TabIndex = 0;
			this.label1.Text = "You are signing the key with the fingerprint";
			// 
			// txtFingerprint
			// 
			this.txtFingerprint.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtFingerprint.Enabled = false;
			this.txtFingerprint.Location = new System.Drawing.Point(4, 24);
			this.txtFingerprint.Name = "txtFingerprint";
			this.txtFingerprint.Size = new System.Drawing.Size(384, 20);
			this.txtFingerprint.TabIndex = 1;
			this.txtFingerprint.Text = "";
			// 
			// groupBox1
			// 
			this.groupBox1.Controls.AddRange(new System.Windows.Forms.Control[] {
																					this.label2,
																					this.chkExportable});
			this.groupBox1.Location = new System.Drawing.Point(4, 96);
			this.groupBox1.Name = "groupBox1";
			this.groupBox1.Size = new System.Drawing.Size(196, 116);
			this.groupBox1.TabIndex = 2;
			this.groupBox1.TabStop = false;
			this.groupBox1.Text = "Exportable";
			// 
			// label2
			// 
			this.label2.Location = new System.Drawing.Point(8, 48);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(184, 64);
			this.label2.TabIndex = 1;
			this.label2.Text = "Check this box if you want others to rely on your signature only!\n\nIf you leave i" +
				"t empty, the signature will only affect your local keyring.";
			// 
			// checkBox1
			// 
			this.chkExportable.Location = new System.Drawing.Point(12, 24);
			this.chkExportable.Name = "chkExportable";
			this.chkExportable.Size = new System.Drawing.Size(156, 16);
			this.chkExportable.TabIndex = 0;
			this.chkExportable.Text = "Exportable";
			// 
			// groupBox2
			// 
			this.groupBox2.Controls.AddRange(new System.Windows.Forms.Control[] {
																					this.rbPositivVerification,
																					this.rbCasualVerification,
																					this.rbNoVerification});
			this.groupBox2.Location = new System.Drawing.Point(208, 96);
			this.groupBox2.Name = "groupBox2";
			this.groupBox2.Size = new System.Drawing.Size(180, 116);
			this.groupBox2.TabIndex = 3;
			this.groupBox2.TabStop = false;
			this.groupBox2.Text = "Verification";
			// 
			// rbNoVerification
			// 
			this.rbNoVerification.Location = new System.Drawing.Point(12, 24);
			this.rbNoVerification.Name = "rbNoVerification";
			this.rbNoVerification.Size = new System.Drawing.Size(152, 16);
			this.rbNoVerification.TabIndex = 0;
			this.rbNoVerification.Text = "No Verification";
			this.rbNoVerification.Checked = true;
			// 
			// rbCasualVerification
			// 
			this.rbCasualVerification.Location = new System.Drawing.Point(12, 44);
			this.rbCasualVerification.Name = "rbCasualVerification";
			this.rbCasualVerification.Size = new System.Drawing.Size(156, 16);
			this.rbCasualVerification.TabIndex = 1;
			this.rbCasualVerification.Text = "Casual Verification";
			// 
			// rbPositivVerification
			// 
			this.rbPositivVerification.Location = new System.Drawing.Point(12, 64);
			this.rbPositivVerification.Name = "rbPositivVerification";
			this.rbPositivVerification.Size = new System.Drawing.Size(156, 16);
			this.rbPositivVerification.TabIndex = 2;
			this.rbPositivVerification.Text = "Positiv Verification";
			// 
			// groupBox3
			// 
			this.groupBox3.Controls.AddRange(new System.Windows.Forms.Control[] {
																					this.label4,
																					this.txtIntroducer,
																					this.label3});
			this.groupBox3.Location = new System.Drawing.Point(4, 216);
			this.groupBox3.Name = "groupBox3";
			this.groupBox3.Size = new System.Drawing.Size(384, 44);
			this.groupBox3.TabIndex = 4;
			this.groupBox3.TabStop = false;
			this.groupBox3.Text = "Trust";
			// 
			// label3
			// 
			this.label3.Location = new System.Drawing.Point(8, 20);
			this.label3.Name = "label3";
			this.label3.Size = new System.Drawing.Size(196, 16);
			this.label3.TabIndex = 0;
			this.label3.Text = "Trust key to introduce up to a depth of";
			// 
			// txtIntroducer
			// 
			this.txtIntroducer.Location = new System.Drawing.Point(220, 16);
			this.txtIntroducer.Name = "txtIntroducer";
			this.txtIntroducer.Size = new System.Drawing.Size(48, 20);
			this.txtIntroducer.TabIndex = 1;
			this.txtIntroducer.Text = "0";
			this.txtIntroducer.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
			// 
			// label4
			// 
			this.label4.Location = new System.Drawing.Point(284, 20);
			this.label4.Name = "label4";
			this.label4.Size = new System.Drawing.Size(64, 16);
			this.label4.TabIndex = 2;
			this.label4.Text = "(0 - 8)";
			// 
			// cmdSign
			// 
			this.cmdSign.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdSign.Location = new System.Drawing.Point(296, 268);
			this.cmdSign.Name = "cmdSign";
			this.cmdSign.Size = new System.Drawing.Size(92, 28);
			this.cmdSign.TabIndex = 5;
			this.cmdSign.Text = "Sign";
			this.cmdSign.Click += new EventHandler(this.cmdSign_Click);
			// 
			// cmdCancel
			// 
			this.cmdCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.cmdCancel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdCancel.Location = new System.Drawing.Point(196, 268);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(92, 28);
			this.cmdCancel.TabIndex = 6;
			this.cmdCancel.Text = "Cancel";
			this.cmdCancel.Click += new EventHandler(this.cmdCancel_Click);
			// 
			// label5
			// 
			this.label5.Location = new System.Drawing.Point(4, 52);
			this.label5.Name = "label5";
			this.label5.Size = new System.Drawing.Size(244, 16);
			this.label5.TabIndex = 7;
			this.label5.Text = "Please select the user id you want to sign";
			// 
			// cmbUserID
			// 
			this.cmbUserID.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.cmbUserID.Location = new System.Drawing.Point(4, 68);
			this.cmbUserID.Name = "cmbUserID";
			this.cmbUserID.Size = new System.Drawing.Size(384, 21);
			this.cmbUserID.TabIndex = 8;
			// 
			// SignKey
			// 
			this.AcceptButton = this.cmdSign;
			this.ShowInTaskbar = false;
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.FormBorderStyle = FormBorderStyle.FixedDialog;
			this.CancelButton = this.cmdCancel;
			this.ClientSize = new System.Drawing.Size(392, 301);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
																		  this.cmbUserID,
																		  this.label5,
																		  this.cmdCancel,
																		  this.cmdSign,
																		  this.groupBox3,
																		  this.groupBox2,
																		  this.groupBox1,
																		  this.txtFingerprint,
																		  this.label1});
			this.Name = "SignKey";
			this.Text = "Adding Key Signature...";
			this.groupBox1.ResumeLayout(false);
			this.groupBox2.ResumeLayout(false);
			this.groupBox3.ResumeLayout(false);
			this.ResumeLayout(false);

		}
		
		private void cmdSign_Click(object sender, System.EventArgs e) {
			int nIntroducerDepth = 0;
			try {
				nIntroducerDepth = Convert.ToInt32(this.txtIntroducer.Text);
			} catch (Exception) {
				MessageBox.Show("Introducer depth must be a number between 0 and 8!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				return;
			}
			if (nIntroducerDepth < 0 || nIntroducerDepth > 8) {
				MessageBox.Show("Introducer depth must be a number between 0 and 8!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				return;
			}
			
			if ((string)cmbUserID.SelectedItem == "") {
				MessageBox.Show("Please select the user ID you want to sign!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				return;
			}
			
			int nType = 0;
			if (this.rbCasualVerification.Checked)
				nType = 0x12;
			if (this.rbNoVerification.Checked)
				nType = 0x11;
			if (this.rbPositivVerification.Checked)
				nType = 0x13;
			
			QueryPassphrase qpPassphrase = new QueryPassphrase();
			qpPassphrase.ShowMultiKeyDialog(SharpPrivacy.SecretKeyRing);
			string strKeyID = xmlKey.GetAttribute("keyid");
			ulong lSignedKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
			ulong lSigningKeyID = qpPassphrase.SelectedKey;
			string strPassphrase = qpPassphrase.Passphrase;
			
			try {
				SharpPrivacy.Instance.SignKey(lSignedKeyID, lSigningKeyID, this.cmbUserID.Text, nIntroducerDepth, chkExportable.Checked, nType, strPassphrase);
			} catch (Exception ex) {
				MessageBox.Show("Something went wrong signing the key: " + ex.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				return;
			}
			
			this.bSigned = true;
			this.Close();
		}
		
		private void cmdCancel_Click(object sender, System.EventArgs e) {
			this.Close();
		}
	}
}

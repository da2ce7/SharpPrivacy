//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// QueryPassphrase.cs: 
// 	GUI for querying passphrase when signing or decrypting.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 23.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;
using System.Collections;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	public class QueryPassphrase : System.Windows.Forms.Form {
		private System.Windows.Forms.Button cmdOK;
		private System.Windows.Forms.Button cmdCancel;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.ComboBox cmbSecretKeys;
		private System.Windows.Forms.TextBox txtPassphrase;
		private System.Windows.Forms.Label label;
		
		// Inner class for Combobox Items
		private class ComboBoxKeyItem {
			private ulong lKeyID;
			private string strItemText;
			
			public ulong KeyID {
				get {
					return lKeyID;
				}
			}
			
			public ComboBoxKeyItem(XmlElement xmlKey) {
				string strSize = xmlKey.GetAttribute("size");
				lKeyID = UInt64.Parse(xmlKey.GetAttribute("keyid").Substring(2), System.Globalization.NumberStyles.HexNumber);
				
				XmlNodeList xnlUserIDs = xmlKey.GetElementsByTagName("UserID");
				string strUserID = ((XmlElement)xnlUserIDs.Item(0)).GetAttribute("name");
				
				strItemText = strUserID + ": 0x" + lKeyID.ToString("x") + " (" + strSize + ")";
			}
			
			public override string ToString() {
				return strItemText;
			}
		}
		
		
		public string Passphrase {
			get {
				return txtPassphrase.Text;
			}
		}
		
		public ulong SelectedKey {
			get {
				if (!(cmbSecretKeys.SelectedItem is ComboBoxKeyItem))
					throw new Exception("Invalid secret key selection!");
				
				return ((ComboBoxKeyItem)cmbSecretKeys.SelectedItem).KeyID;
			}
		}
		
		public QueryPassphrase() {
			InitializeComponent();
			this.AcceptButton = cmdOK;
			this.CancelButton = cmdCancel;
		}
		
		/// <summary>
		/// Shows a dialog asking the user to enter a passphrase
		/// for a symmetrically encrypted message
		/// </summary>
		public void ShowMyDialog() {
			this.cmbSecretKeys.Items.Clear();
			this.cmbSecretKeys.Enabled = false;
			this.ShowDialog();
		}
		
		/// <summary>
		/// Shows a dialog asking the user to enter a passphrase
		/// for a symmetrically encrypted message
		/// </summary>
		public void ShowSingleKeyDialog(System.Xml.XmlElement xmlKey) {
			this.cmbSecretKeys.Items.Clear();
			this.cmbSecretKeys.Enabled = false;
			
			if (xmlKey.Name != "SecretKey")			
				throw new ArgumentException("You have to give exactly one key as argument to ShowSingleKeyDialog!");
			
			ComboBoxKeyItem cbkiKey = new ComboBoxKeyItem(xmlKey);
			this.cmbSecretKeys.Items.Add(cbkiKey);
			this.cmbSecretKeys.SelectedIndex = 0;
			this.ShowDialog();
		}
		
		public void ShowMultiKeyDialog(System.Xml.XmlElement xmlKeyRing) {
			this.cmbSecretKeys.Items.Clear();
			this.cmbSecretKeys.Enabled = true;
			
			XmlNodeList xnlSecretKeys = xmlKeyRing.GetElementsByTagName("SecretKey");
			IEnumerator ieKeys = xnlSecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				XmlElement xmlKey = (XmlElement)ieKeys.Current;
				
				ComboBoxKeyItem cbkiKey = new ComboBoxKeyItem(xmlKey);
				cmbSecretKeys.Items.Add(cbkiKey);
			}
			
			cmbSecretKeys.SelectedIndex = 0;
			
			this.ShowDialog();
		}
		
		void InitializeComponent() {
			this.label = new System.Windows.Forms.Label();
			this.txtPassphrase = new System.Windows.Forms.TextBox();
			this.cmbSecretKeys = new System.Windows.Forms.ComboBox();
			this.label2 = new System.Windows.Forms.Label();
			this.cmdCancel = new System.Windows.Forms.Button();
			this.cmdOK = new System.Windows.Forms.Button();
			this.SuspendLayout();
			// 
			// label
			// 
			this.label.Location = new System.Drawing.Point(0, 56);
			this.label.Name = "label";
			this.label.Size = new System.Drawing.Size(176, 16);
			this.label.TabIndex = 0;
			this.label.Text = "Please enter your passphrase:";
			// 
			// txtPassphrase
			// 
			this.txtPassphrase.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtPassphrase.Location = new System.Drawing.Point(2, 72);
			this.txtPassphrase.Name = "txtPassphrase";
			this.txtPassphrase.PasswordChar = '*';
			this.txtPassphrase.Size = new System.Drawing.Size(443, 20);
			this.txtPassphrase.TabIndex = 1;
			this.txtPassphrase.Text = "";
			// 
			// cmbSecretKeys
			// 
			this.cmbSecretKeys.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.cmbSecretKeys.Location = new System.Drawing.Point(3, 24);
			this.cmbSecretKeys.Name = "cmbSecretKeys";
			this.cmbSecretKeys.Size = new System.Drawing.Size(440, 21);
			this.cmbSecretKeys.TabIndex = 4;
			// 
			// label2
			// 
			this.label2.Location = new System.Drawing.Point(2, 8);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(200, 16);
			this.label2.TabIndex = 5;
			this.label2.Text = "Select your secret key:";
			// 
			// cmdCancel
			// 
			this.cmdCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.cmdCancel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdCancel.Location = new System.Drawing.Point(216, 104);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(112, 24);
			this.cmdCancel.TabIndex = 3;
			this.cmdCancel.Text = "Cancel";
			// 
			// cmdOK
			// 
			this.cmdOK.DialogResult = System.Windows.Forms.DialogResult.OK;
			this.cmdOK.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdOK.Location = new System.Drawing.Point(333, 104);
			this.cmdOK.Name = "cmdOK";
			this.cmdOK.Size = new System.Drawing.Size(112, 24);
			this.cmdOK.TabIndex = 2;
			this.cmdOK.Text = "OK";
			// 
			// QueryPassphrase
			// 
			this.ClientSize = new System.Drawing.Size(448, 135);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.label2,
						this.cmbSecretKeys,
						this.cmdCancel,
						this.cmdOK,
						this.txtPassphrase,
						this.label});
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.ShowInTaskbar = false;
			this.Text = "Please Enter Your Passphrase...";
			this.ResumeLayout(false);
		}
	}
}

//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// KeyProperties.cs: 
// 	This class is a GUI that shows the key properties of a public key.
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
	/// Summary description for KeyProperties.
	/// </summary>
	public class KeyProperties : System.Windows.Forms.Form {
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.TextBox txtFingerprint;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.TextBox txtTimeCreated;
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.TextBox txtKeyID;
		private System.Windows.Forms.TextBox txtExpiration;
		private System.Windows.Forms.Label label4;
		private System.Windows.Forms.Label label5;
		private System.Windows.Forms.TextBox txtAlgorithm;
		private System.Windows.Forms.Label label6;
		private System.Windows.Forms.TextBox txtType;
		private System.Windows.Forms.TabControl tcTabs;
		private System.Windows.Forms.TabPage tpUserID;
		private System.Windows.Forms.TabPage tpSubKeys;
		private System.Windows.Forms.Button cmdOK;
		private System.Windows.Forms.ListView lvSubkeys;
		private System.Windows.Forms.ColumnHeader chKeyType;
		private System.Windows.Forms.ColumnHeader chLength;
		private System.Windows.Forms.ColumnHeader chFingerprint;
		private System.Windows.Forms.ListView lvUserIDs;
		private System.Windows.Forms.ColumnHeader chUserID;
		private System.Windows.Forms.ColumnHeader chSignatures;
		
		private XmlElement xmlKey;

		public KeyProperties(XmlElement xmlKey) {
			this.xmlKey = xmlKey;
			InitializeComponent();
			PopulateComponents();
		}
		
		private void PopulateComponents() {
			this.txtKeyID.Text = xmlKey.GetAttribute("keyid");
			this.txtFingerprint.Text = xmlKey.GetAttribute("fingerprint");
			string strTimeCreated = xmlKey.GetAttribute("created");
			DateTime dtTimeCreated = new DateTime(Int64.Parse(strTimeCreated));
			this.txtTimeCreated.Text = dtTimeCreated.ToString();
			string strExpiration = xmlKey.GetAttribute("expiration");
			if (strExpiration != "never") {
				DateTime dtExpiration = new DateTime(Int64.Parse(strExpiration));
				strExpiration = dtExpiration.ToString();
			}
			this.txtExpiration.Text = strExpiration;
			
			string strSize = xmlKey.GetAttribute("size");
			this.txtType.Text = xmlKey.GetAttribute("algorithm");
			this.txtAlgorithm.Text = xmlKey.GetAttribute("algorithm");
			
			XmlNodeList xnlSubkeys = xmlKey.GetElementsByTagName("Subkey");
			IEnumerator ieSubkeys = xnlSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				XmlElement xmlSubkey = (XmlElement)ieSubkeys.Current;
				
				System.Windows.Forms.ListViewItem lviItem = new ListViewItem(xmlSubkey.GetAttribute("algorithm"));
				lviItem.SubItems.Add(xmlSubkey.GetAttribute("size") + " Bit");
				lviItem.SubItems.Add(xmlSubkey.GetAttribute("fingerprint"));
				lvSubkeys.Items.Add(lviItem);
			}
			
			// Add UserIDs
			XmlNodeList xnlUserIDs = xmlKey.GetElementsByTagName("UserID");
			IEnumerator ieUserIDs = xnlUserIDs.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				XmlElement xmlUserID = (XmlElement)ieUserIDs.Current;
				
				string strName = xmlUserID.GetAttribute("name");
				string strCreated = xmlUserID.GetAttribute("created");
				string strPrimary = xmlUserID.GetAttribute("primary");

				DateTime dtCreated = new DateTime(Int64.Parse(strCreated));
				strCreated = dtCreated.ToString();

				XmlNodeList xnlSignatures = xmlUserID.GetElementsByTagName("Signature");

				ListViewItem lviItem = new ListViewItem(strName);
				lviItem.SubItems.Add(xnlSignatures.Count.ToString());
				this.lvUserIDs.Items.Add(lviItem);
			}
		}
		
		private void InitializeComponent() {
			this.label1 = new System.Windows.Forms.Label();
			this.txtFingerprint = new System.Windows.Forms.TextBox();
			this.label2 = new System.Windows.Forms.Label();
			this.txtTimeCreated = new System.Windows.Forms.TextBox();
			this.label3 = new System.Windows.Forms.Label();
			this.txtKeyID = new System.Windows.Forms.TextBox();
			this.txtExpiration = new System.Windows.Forms.TextBox();
			this.label4 = new System.Windows.Forms.Label();
			this.label5 = new System.Windows.Forms.Label();
			this.txtAlgorithm = new System.Windows.Forms.TextBox();
			this.label6 = new System.Windows.Forms.Label();
			this.txtType = new System.Windows.Forms.TextBox();
			this.tcTabs = new System.Windows.Forms.TabControl();
			this.tpUserID = new System.Windows.Forms.TabPage();
			this.lvUserIDs = new System.Windows.Forms.ListView();
			this.chUserID = new System.Windows.Forms.ColumnHeader();
			this.chSignatures = new System.Windows.Forms.ColumnHeader();
			this.tpSubKeys = new System.Windows.Forms.TabPage();
			this.lvSubkeys = new System.Windows.Forms.ListView();
			this.chKeyType = new System.Windows.Forms.ColumnHeader();
			this.chLength = new System.Windows.Forms.ColumnHeader();
			this.chFingerprint = new System.Windows.Forms.ColumnHeader();
			this.cmdOK = new System.Windows.Forms.Button();
			this.tcTabs.SuspendLayout();
			this.tpUserID.SuspendLayout();
			this.tpSubKeys.SuspendLayout();
			this.SuspendLayout();
			// 
			// label1
			// 
			this.label1.Location = new System.Drawing.Point(4, 8);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(108, 16);
			this.label1.TabIndex = 0;
			this.label1.Text = "Fingerprint";
			// 
			// txtFingerprint
			// 
			this.txtFingerprint.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtFingerprint.Enabled = false;
			this.txtFingerprint.Location = new System.Drawing.Point(4, 24);
			this.txtFingerprint.Name = "txtFingerprint";
			this.txtFingerprint.Size = new System.Drawing.Size(284, 20);
			this.txtFingerprint.TabIndex = 1;
			this.txtFingerprint.Text = "";
			this.txtFingerprint.TextAlign = HorizontalAlignment.Center;
			// 
			// label2
			// 
			this.label2.Location = new System.Drawing.Point(8, 84);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(76, 16);
			this.label2.TabIndex = 2;
			this.label2.Text = "Time Created";
			// 
			// txtTimeCreated
			// 
			this.txtTimeCreated.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtTimeCreated.Enabled = false;
			this.txtTimeCreated.Location = new System.Drawing.Point(104, 80);
			this.txtTimeCreated.Name = "txtTimeCreated";
			this.txtTimeCreated.Size = new System.Drawing.Size(124, 20);
			this.txtTimeCreated.TabIndex = 3;
			this.txtTimeCreated.Text = "";
			// 
			// label3
			// 
			this.label3.Location = new System.Drawing.Point(8, 108);
			this.label3.Name = "label3";
			this.label3.Size = new System.Drawing.Size(72, 16);
			this.label3.TabIndex = 4;
			this.label3.Text = "Key ID";
			// 
			// txtKeyID
			// 
			this.txtKeyID.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtKeyID.Enabled = false;
			this.txtKeyID.Location = new System.Drawing.Point(104, 104);
			this.txtKeyID.Name = "txtKeyID";
			this.txtKeyID.Size = new System.Drawing.Size(124, 20);
			this.txtKeyID.TabIndex = 5;
			this.txtKeyID.Text = "";
			// 
			// txtExpiration
			// 
			this.txtExpiration.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtExpiration.Enabled = false;
			this.txtExpiration.Location = new System.Drawing.Point(104, 128);
			this.txtExpiration.Name = "txtExpiration";
			this.txtExpiration.Size = new System.Drawing.Size(124, 20);
			this.txtExpiration.TabIndex = 6;
			this.txtExpiration.Text = "";
			// 
			// label4
			// 
			this.label4.Location = new System.Drawing.Point(8, 132);
			this.label4.Name = "label4";
			this.label4.Size = new System.Drawing.Size(76, 16);
			this.label4.TabIndex = 7;
			this.label4.Text = "Expires";
			// 
			// label5
			// 
			this.label5.Location = new System.Drawing.Point(8, 156);
			this.label5.Name = "label5";
			this.label5.Size = new System.Drawing.Size(140, 16);
			this.label5.TabIndex = 8;
			this.label5.Text = "Prefered Algorithm";
			// 
			// txtAlgorithm
			// 
			this.txtAlgorithm.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtAlgorithm.Enabled = false;
			this.txtAlgorithm.Location = new System.Drawing.Point(104, 152);
			this.txtAlgorithm.Name = "txtAlgorithm";
			this.txtAlgorithm.Size = new System.Drawing.Size(124, 20);
			this.txtAlgorithm.TabIndex = 9;
			this.txtAlgorithm.Text = "";
			// 
			// label6
			// 
			this.label6.Location = new System.Drawing.Point(8, 60);
			this.label6.Name = "label6";
			this.label6.Size = new System.Drawing.Size(80, 16);
			this.label6.TabIndex = 10;
			this.label6.Text = "Type";
			// 
			// txtType
			// 
			this.txtType.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtType.Enabled = false;
			this.txtType.Location = new System.Drawing.Point(104, 56);
			this.txtType.Name = "txtType";
			this.txtType.Size = new System.Drawing.Size(124, 20);
			this.txtType.TabIndex = 11;
			this.txtType.Text = "";
			// 
			// tcTabs
			// 
			this.tcTabs.Controls.AddRange(new System.Windows.Forms.Control[] {
																				 this.tpUserID,
																				 this.tpSubKeys});
			this.tcTabs.Location = new System.Drawing.Point(4, 180);
			this.tcTabs.Name = "tcTabs";
			this.tcTabs.SelectedIndex = 0;
			this.tcTabs.Size = new System.Drawing.Size(284, 172);
			this.tcTabs.TabIndex = 12;
			// 
			// tpUserID
			// 
			this.tpUserID.Controls.AddRange(new System.Windows.Forms.Control[] {
																				   this.lvUserIDs});
			this.tpUserID.Location = new System.Drawing.Point(4, 22);
			this.tpUserID.Name = "tpUserID";
			this.tpUserID.Size = new System.Drawing.Size(276, 146);
			this.tpUserID.TabIndex = 0;
			this.tpUserID.Text = "User IDs";
			// 
			// lvUserIDs
			// 
			this.lvUserIDs.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.lvUserIDs.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
																						this.chUserID,
																						this.chSignatures});
			this.lvUserIDs.Location = new System.Drawing.Point(4, 4);
			this.lvUserIDs.Name = "lvUserIDs";
			this.lvUserIDs.Size = new System.Drawing.Size(268, 140);
			this.lvUserIDs.TabIndex = 0;
			this.lvUserIDs.View = System.Windows.Forms.View.Details;
			// 
			// chUserID
			// 
			this.chUserID.Text = "UserID";
			this.chUserID.Width = 193;
			// 
			// chSignatures
			// 
			this.chSignatures.Text = "Signatures";
			this.chSignatures.Width = 69;
			// 
			// tpSubKeys
			// 
			this.tpSubKeys.Controls.AddRange(new System.Windows.Forms.Control[] {
																					this.lvSubkeys});
			this.tpSubKeys.Location = new System.Drawing.Point(4, 22);
			this.tpSubKeys.Name = "tpSubKeys";
			this.tpSubKeys.Size = new System.Drawing.Size(276, 146);
			this.tpSubKeys.TabIndex = 1;
			this.tpSubKeys.Text = "Subkeys";
			// 
			// lvSubkeys
			// 
			this.lvSubkeys.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.lvSubkeys.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
																						this.chKeyType,
																						this.chLength,
																						this.chFingerprint});
			this.lvSubkeys.Location = new System.Drawing.Point(4, 8);
			this.lvSubkeys.Name = "lvSubkeys";
			this.lvSubkeys.Size = new System.Drawing.Size(268, 136);
			this.lvSubkeys.TabIndex = 0;
			this.lvSubkeys.View = System.Windows.Forms.View.Details;
			// 
			// chKeyType
			// 
			this.chKeyType.Text = "Type";
			this.chKeyType.Width = 88;
			// 
			// chLength
			// 
			this.chLength.Text = "Length";
			// 
			// chFingerprint
			// 
			this.chFingerprint.Text = "Fingerprint";
			// 
			// cmdOK
			// 
			this.cmdOK.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.cmdOK.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdOK.Location = new System.Drawing.Point(176, 360);
			this.cmdOK.Name = "cmdOK";
			this.cmdOK.Size = new System.Drawing.Size(112, 28);
			this.cmdOK.TabIndex = 13;
			this.cmdOK.Text = "OK";
			this.cmdOK.Click += new EventHandler(this.cmdOK_Click);
			// 
			// KeyProperties
			// 
			this.AcceptButton = this.cmdOK;
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.ClientSize = new System.Drawing.Size(292, 393);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
																		  this.cmdOK,
																		  this.tcTabs,
																		  this.txtType,
																		  this.label6,
																		  this.txtAlgorithm,
																		  this.label5,
																		  this.label4,
																		  this.txtExpiration,
																		  this.txtKeyID,
																		  this.label3,
																		  this.txtTimeCreated,
																		  this.label2,
																		  this.txtFingerprint,
																		  this.label1});
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.Name = "KeyProperties";
			this.ShowInTaskbar = false;
			this.Text = "Key Properties...";
			this.tcTabs.ResumeLayout(false);
			this.tpUserID.ResumeLayout(false);
			this.tpSubKeys.ResumeLayout(false);
			this.ResumeLayout(false);

		}
		
		private void cmdOK_Click(object sender, EventArgs e) {
			this.Close();
		}

	}
}

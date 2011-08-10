//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// PublicKeySelector.cs: 
// 	This class is a GUI that asks the user to which public keys he
//	wants to encrypt.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 01.05.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	public class PublicKeySelector : System.Windows.Forms.Form {
		private System.Windows.Forms.ListView lstAll;
		private System.Windows.Forms.Button cmdEncrypt;
		private System.Windows.Forms.Button cmdCancel;
		private System.Windows.Forms.Label label;
		
		private System.Windows.Forms.ImageList imlKeys;
		private ArrayList alSelectedKeys = new ArrayList();
		
		public ArrayList SelectedKeys {
			get {
				return alSelectedKeys;
			}
		}
		
		public PublicKeySelector(XmlElement xmlPublicKeyRing) {
			InitializeComponent();
			InitializeMyComponent();
			
			FillListViews(xmlPublicKeyRing);
		}
		
		void FillListViews(XmlElement xmlPublicKeyRing) {
			XmlNodeList xnlPublicKeyRing = xmlPublicKeyRing.GetElementsByTagName("PublicKey");
			IEnumerator ieKeys = xnlPublicKeyRing.GetEnumerator();
			while (ieKeys.MoveNext()) {
				XmlElement xmlPublicKey = (XmlElement)ieKeys.Current;
				
				System.Windows.Forms.ListViewItem lviItem = new ListViewItem();
				
				string strSize = xmlPublicKey.GetAttribute("size");
				XmlNodeList xnlPublicKey = xmlPublicKey.GetElementsByTagName("Subkey");
				IEnumerator ieSubkeys = xnlPublicKey.GetEnumerator();
				while (ieSubkeys.MoveNext())
					strSize += "/" + ((XmlElement)ieSubkeys.Current).GetAttribute("size");
				
				xnlPublicKey = xmlPublicKey.GetElementsByTagName("UserID");
				string strPrimaryUserID = "";
				IEnumerator ieUserIDs = xnlPublicKey.GetEnumerator();
				while (ieUserIDs.MoveNext()) {
					XmlElement xmlUserID = (XmlElement)ieUserIDs.Current;
					
					if (xmlUserID.GetAttribute("primary") == "true")
						strPrimaryUserID = xmlUserID.GetAttribute("name");
				}
				
				lviItem.Text = strPrimaryUserID;
				lviItem.SubItems.Add(strSize);
				lviItem.SubItems.Add(xmlPublicKey.GetAttribute("keyid"));
				DateTime dtTimeCreated = new DateTime(Int64.Parse(xmlPublicKey.GetAttribute("created")));
				lviItem.SubItems.Add(dtTimeCreated.ToString());
				lviItem.Tag = UInt64.Parse(xmlPublicKey.GetAttribute("keyid").Substring(2), System.Globalization.NumberStyles.HexNumber);
				
				lviItem.ImageIndex = 0;
				lstAll.Items.Add(lviItem);
			}
		}
		
		void InitializeMyComponent() {
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", System.Reflection.Assembly.GetExecutingAssembly()); 
			
			this.cmdCancel.Click += new EventHandler(this.cmdCancel_Click);
			this.cmdEncrypt.Click += new EventHandler(this.cmdEncrypt_Click);
			
			this.imlKeys = new System.Windows.Forms.ImageList();
			this.imlKeys.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
			this.imlKeys.ImageSize = new System.Drawing.Size(16, 16);
			this.imlKeys.TransparentColor = System.Drawing.Color.Transparent;
			this.imlKeys.Images.Add((System.Drawing.Icon)resources.GetObject("listPublicKey"));
			this.lstAll.SmallImageList = this.imlKeys;
			
			ColumnHeader chKey = new ColumnHeader();
			ColumnHeader chSize = new ColumnHeader();
			ColumnHeader chKeyID = new ColumnHeader();
			ColumnHeader chCreated = new ColumnHeader();
			
			chKey.Width = 160;
			chSize.Width = 60;
			chKeyID.Width = 100;
			chCreated.Width = 120;
			
			this.lstAll.Columns.Add(chKey);
			this.lstAll.Columns.Add(chSize);
			this.lstAll.Columns.Add(chKeyID);
			this.lstAll.Columns.Add(chCreated);
			
			this.AcceptButton = cmdEncrypt;
			this.CancelButton = cmdCancel;
		}
		
		// THIS METHOD IS MAINTAINED BY THE FORM DESIGNER
		// DO NOT EDIT IT MANUALLY! YOUR CHANGES ARE LIKELY TO BE LOST
		void InitializeComponent() {
			this.label = new System.Windows.Forms.Label();
			this.cmdCancel = new System.Windows.Forms.Button();
			this.cmdEncrypt = new System.Windows.Forms.Button();
			this.lstAll = new System.Windows.Forms.ListView();
			this.SuspendLayout();
			// 
			// label
			// 
			this.label.Location = new System.Drawing.Point(4, 8);
			this.label.Name = "label";
			this.label.Size = new System.Drawing.Size(256, 16);
			this.label.TabIndex = 0;
			this.label.Text = "Please select the keys you want to encrypt to";
			// 
			// cmdCancel
			// 
			this.cmdCancel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdCancel.Location = new System.Drawing.Point(244, 320);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(108, 28);
			this.cmdCancel.TabIndex = 5;
			this.cmdCancel.Text = "Cancel";
			// 
			// cmdEncrypt
			// 
			this.cmdEncrypt.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdEncrypt.Location = new System.Drawing.Point(360, 320);
			this.cmdEncrypt.Name = "cmdEncrypt";
			this.cmdEncrypt.Size = new System.Drawing.Size(108, 28);
			this.cmdEncrypt.TabIndex = 4;
			this.cmdEncrypt.Text = "Encrypt";
			// 
			// lstAll
			// 
			this.lstAll.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.lstAll.CheckBoxes = true;
			this.lstAll.Location = new System.Drawing.Point(4, 24);
			this.lstAll.Name = "lstAll";
			this.lstAll.Size = new System.Drawing.Size(464, 288);
			this.lstAll.TabIndex = 1;
			this.lstAll.View = System.Windows.Forms.View.Details;
			// 
			// PublicKeySelector
			// 
			this.ClientSize = new System.Drawing.Size(472, 353);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.cmdCancel,
						this.cmdEncrypt,
						this.lstAll,
						this.label});
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Text = "Public Keys...";
			this.ResumeLayout(false);
		}
		
		void cmdCancel_Click(Object sender, System.EventArgs e) {
			this.alSelectedKeys = new ArrayList();
			this.Hide();
		}
		
		void cmdEncrypt_Click(Object sender, System.EventArgs e) {
			int iCount = 0;
			IEnumerator ieItems = this.lstAll.Items.GetEnumerator();
			while (ieItems.MoveNext()) {
				ListViewItem lviItem = (ListViewItem)ieItems.Current;
				if (lviItem.Checked) {
					alSelectedKeys.Add(lviItem.Tag);
					iCount++;
				}
			}
			
			if (iCount > 0)
				this.Hide();
			else 
				MessageBox.Show("You have to at least select one key you want to encrypt to!", "Error...");
		}
		
	}
}

//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// PlaintextViewer.cs: 
// 	This class is a GUI for showing the plaintext after decrypting it.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 04.05.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;
using System.Xml;
using System.IO;

namespace SharpPrivacy.SharpPrivacyTray {
	public class PlaintextViewer : System.Windows.Forms.Form {
		private System.Windows.Forms.RichTextBox rtbMessage;
		private System.Windows.Forms.Button cmdClipboard;
		private System.Windows.Forms.Button cmdClose;
		private string strXmlMessage;
		private string strDataFormat;
		private string strTimeCreated;
		private string strFilename;
		private string strText;
		private string strLiteralMessage;
		
		public string MessageText {
			get {
				return rtbMessage.Text;
			}
			set {
				rtbMessage.Text = value;
			}
		}
		
		public string XmlMessage {
			get {
				return strXmlMessage;
			}
			set {
				strXmlMessage = value;
				
				//Interprete the xml we got and set the
				//message text accordingly
				XmlDocument xmlDoc = new XmlDocument();
				xmlDoc.LoadXml(strXmlMessage);
				XmlElement xmlMessage = xmlDoc.DocumentElement;
				
				if (xmlMessage.Name != "OpenPGPMessage") {
					MessageBox.Show("Expected an Xml text but did not find one!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					return;
				}
				
				string strAsymEncrypted;
				string strSymEncrypted;
				string strSigned;
				try {
					strAsymEncrypted = xmlMessage.GetAttribute("asymmetricallyencrypted");
					strSymEncrypted = xmlMessage.GetAttribute("symmetricallyencrypted");
					strSigned = xmlMessage.GetAttribute("signed");
				} catch (XmlException) {
					MessageBox.Show("Xml message is not in a valid format!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					return;
				}
				
				if (strSigned == "True") {
					strText += "***** Signed Message *****\n";
					try {
						strText += "Signature Status: " + xmlMessage.GetAttribute("signaturestatus") + "\n";
						strText += "Signing Key: " + xmlMessage.GetAttribute("signingkey") + "\n";
						long lTicks = Int64.Parse(xmlMessage.GetAttribute("signingdate"));
						DateTime dtSigned = new DateTime(lTicks);
						strText += "Signing Date: " + dtSigned.ToString() + "\n";
					} catch (Exception) {
						MessageBox.Show("Xml message is not in a valid format!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					}
				}
				
				if (strSymEncrypted == "True")
					strText += "***** Symmetrically Encrypted Message *****\n";
				
				if (strAsymEncrypted == "True")
					strText += "***** Asymmetrically Encrypted Message *****\n";
				
				
				try {
					XmlNodeList xnlLiteral = xmlMessage.GetElementsByTagName("LiteralMessage");
					XmlElement xmlLiteralMessage = (XmlElement)xnlLiteral.Item(0);
					
					strDataFormat = xmlLiteralMessage.GetAttribute("dataformat");
					strTimeCreated = xmlLiteralMessage.GetAttribute("timecreated");
					strFilename = xmlLiteralMessage.GetAttribute("filename");
					
					long lTicks = Int64.Parse(strTimeCreated);
					DateTime dtTimeCreated = new DateTime(lTicks);
					
					strText += "Data Format: " + strDataFormat + "\n";
					strText += "Time Created: " + dtTimeCreated.ToString() + "\n";
					
					if (strDataFormat != "Binary")
						strText += "\n" + xmlLiteralMessage.InnerText + "\n";
					else
						strLiteralMessage = xmlLiteralMessage.InnerText;
					
					strText += "***** End OpenPGP Message *****\n";
				} catch (Exception) {
					MessageBox.Show("Xml message is not in a valid format!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
				}
				
			}
		}
		
		public PlaintextViewer() {
			InitializeComponent();
			this.AcceptButton = cmdClose;
			this.Resize += new System.EventHandler(this.PlaintextViewerResize);
			rtbMessage.Focus();
		}
		
		void cmdCloseClick(object sender, System.EventArgs e) {
			this.Hide();
		}
		
		void cmdClipboardClick(object sender, System.EventArgs e) {
			Clipboard.SetDataObject(rtbMessage.Text);
		}
		
		public void ShowPlaintext() {
			if ((strDataFormat == "Binary") || (strFilename.Length > 0)) {
				string strMessageBox = "\nDo you want to save the included file on your harddisk?";
				if (MessageBox.Show(strText+ strMessageBox, "Encrypted/Signed OpenPGP File...", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1) == DialogResult.OK) {
					System.Windows.Forms.SaveFileDialog sfdSave = new SaveFileDialog();
					sfdSave.OverwritePrompt = true;
					sfdSave.Filter = "All Files (*.*)|*.*";
					sfdSave.FileName = strFilename;
					sfdSave.ShowDialog();
					if (sfdSave.FileName.Length > 0) {
						System.IO.FileStream fsOut = new FileStream(sfdSave.FileName, FileMode.Create);
						System.IO.BinaryWriter bwOut = new BinaryWriter(fsOut);
						bwOut.Write(Convert.FromBase64String(strLiteralMessage));
						bwOut.Close();
						fsOut.Close();
					}
				}
			} else {
				this.rtbMessage.Text = strText;
				base.Show();
			}
		}
		
		void PlaintextViewerResize(object sender, System.EventArgs e) {
			cmdClose.Location = new System.Drawing.Point(this.ClientSize.Width - 128, this.ClientSize.Height - 27);
			cmdClipboard.Location = new System.Drawing.Point(this.ClientSize.Width - 259, this.ClientSize.Height - 27);
			rtbMessage.Width = this.ClientSize.Width - 8;
			rtbMessage.Height = this.ClientSize.Height - 36; 
		}
		
		// THIS METHOD IS MAINTAINED BY THE FORM DESIGNER
		// DO NOT EDIT IT MANUALLY! YOUR CHANGES ARE LIKELY TO BE LOST
		void InitializeComponent() {
			this.cmdClose = new System.Windows.Forms.Button();
			this.cmdClipboard = new System.Windows.Forms.Button();
			this.rtbMessage = new System.Windows.Forms.RichTextBox();
			this.SuspendLayout();
			// 
			// cmdClose
			// 
			this.cmdClose.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdClose.Location = new System.Drawing.Point(432, 320);
			this.cmdClose.Name = "cmdClose";
			this.cmdClose.Size = new System.Drawing.Size(124, 24);
			this.cmdClose.TabIndex = 1;
			this.cmdClose.Text = "Close";
			this.cmdClose.Click += new System.EventHandler(this.cmdCloseClick);
			// 
			// cmdClipboard
			// 
			this.cmdClipboard.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdClipboard.Location = new System.Drawing.Point(300, 320);
			this.cmdClipboard.Name = "cmdClipboard";
			this.cmdClipboard.Size = new System.Drawing.Size(124, 24);
			this.cmdClipboard.TabIndex = 0;
			this.cmdClipboard.Text = "Copy To Clipboard";
			this.cmdClipboard.Click += new System.EventHandler(this.cmdClipboardClick);
			// 
			// rtbMessage
			// 
			this.rtbMessage.Font = new System.Drawing.Font("Courier New", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((System.Byte)(0)));
			this.rtbMessage.Location = new System.Drawing.Point(4, 4);
			this.rtbMessage.Name = "rtbMessage";
			this.rtbMessage.ReadOnly = true;
			this.rtbMessage.Size = new System.Drawing.Size(552, 312);
			this.rtbMessage.TabIndex = 2;
			this.rtbMessage.Text = "";
			// 
			// PlaintextViewer
			// 
			this.ClientSize = new System.Drawing.Size(560, 349);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.rtbMessage,
						this.cmdClose,
						this.cmdClipboard});
			this.Text = "Decrypted Message...";
			this.ResumeLayout(false);
		}
	}
}

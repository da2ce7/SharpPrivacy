//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// PacketParser.cs: 
// 	GUI for packet parsing.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 20.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;

namespace SharpPrivacy.SharpPrivacyTray {
	public class PacketParser : System.Windows.Forms.Form {
		private System.Windows.Forms.Label label;
		private System.Windows.Forms.TextBox txtKeyProperties;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.TextBox txtBase64Key;
		private System.Windows.Forms.Button cmdClose;
		private System.Windows.Forms.Button cmdParse;
		
		public PacketParser() {
			InitializeComponent();
			this.AcceptButton = cmdParse;
			this.CancelButton = cmdClose;
			cmdClose.Click += new EventHandler(cmdClose_Click);
			cmdParse.Click += new EventHandler(cmdParse_Click);

		}
		
		void InitializeComponent() {
			this.cmdParse = new System.Windows.Forms.Button();
			this.cmdClose = new System.Windows.Forms.Button();
			this.txtBase64Key = new System.Windows.Forms.TextBox();
			this.label2 = new System.Windows.Forms.Label();
			this.txtKeyProperties = new System.Windows.Forms.TextBox();
			this.label = new System.Windows.Forms.Label();
			this.SuspendLayout();
			// 
			// cmdParse
			// 
			this.cmdParse.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdParse.Location = new System.Drawing.Point(256, 368);
			this.cmdParse.Name = "cmdParse";
			this.cmdParse.Size = new System.Drawing.Size(104, 24);
			this.cmdParse.TabIndex = 2;
			this.cmdParse.Text = "Parse";
			// 
			// cmdClose
			// 
			this.cmdClose.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			this.cmdClose.Location = new System.Drawing.Point(368, 368);
			this.cmdClose.Name = "cmdClose";
			this.cmdClose.Size = new System.Drawing.Size(104, 24);
			this.cmdClose.TabIndex = 3;
			this.cmdClose.Text = "Close";
			// 
			// txtBase64Key
			// 
			this.txtBase64Key.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtBase64Key.Location = new System.Drawing.Point(8, 24);
			this.txtBase64Key.Multiline = true;
			this.txtBase64Key.Name = "txtBase64Key";
			this.txtBase64Key.Size = new System.Drawing.Size(232, 336);
			this.txtBase64Key.TabIndex = 0;
			this.txtBase64Key.Text = "";
			// 
			// label2
			// 
			this.label2.Location = new System.Drawing.Point(248, 8);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(120, 16);
			this.label2.TabIndex = 3;
			this.label2.Text = "Contained Packets";
			// 
			// txtKeyProperties
			// 
			this.txtKeyProperties.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
			this.txtKeyProperties.Location = new System.Drawing.Point(248, 24);
			this.txtKeyProperties.Multiline = true;
			this.txtKeyProperties.Name = "txtKeyProperties";
			this.txtKeyProperties.Size = new System.Drawing.Size(224, 336);
			this.txtKeyProperties.TabIndex = 1;
			this.txtKeyProperties.Text = "";
			// 
			// label
			// 
			this.label.Location = new System.Drawing.Point(8, 8);
			this.label.Name = "label";
			this.label.Size = new System.Drawing.Size(208, 16);
			this.label.TabIndex = 0;
			this.label.Text = "Base64 Encoded OpenPGP Message";
			// 
			// PacketParser
			// 
			this.ClientSize = new System.Drawing.Size(480, 397);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.cmdParse,
						this.cmdClose,
						this.txtBase64Key,
						this.label2,
						this.txtKeyProperties,
						this.label});
			this.ResumeLayout(false);
		}
		
		void cmdParse_Click(Object sender, System.EventArgs e) {
			Packet[] pKeys = Packet.ParsePackets(txtBase64Key.Text);

			string strKeys = "";
			for (int i=0; i<pKeys.Length; i++) {
				/* As soon as all Packets are implemented, replace
				 * this by a simple pKeys[i].ToString();
				 * For now we need all the ifs
				 */
				if (pKeys[i] is PublicKeyPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is UserIDPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is SignaturePacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is SymmetricallyEncryptedDataPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is AsymSessionKeyPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is SymSessionKeyPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is LiteralDataPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is CompressedDataPacket) {
					strKeys += pKeys[i].ToString();
				} else if (pKeys[i] is SecretKeyPacket) {
					QueryPassphrase queryPassphrase = new QueryPassphrase();
					queryPassphrase.ShowMyDialog();
					string strPassphrase = queryPassphrase.Passphrase;
					SecretKeyPacket skpPacket = (SecretKeyPacket)pKeys[i];
					skpPacket.GetDecryptedKeyMaterial(strPassphrase);
					strKeys += pKeys[i].ToString();
				}
			}
			this.txtKeyProperties.Lines = strKeys.Split('\n');
		}

		void cmdClose_Click(Object sender, System.EventArgs e) {
			this.Hide();
		}
		
	}
}

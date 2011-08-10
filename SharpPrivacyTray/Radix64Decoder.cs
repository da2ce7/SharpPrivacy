//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// Radix64Decoder.cs: 
// 	GUI for decoding radix64 values.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 12.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;

namespace SharpPrivacy.SharpPrivacyTray {
	public class Radix64Decoder : System.Windows.Forms.Form {
		private System.Windows.Forms.TextBox txtRadix64;
		private System.Windows.Forms.Label label;
		private System.Windows.Forms.TextBox txtPlaintext;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.Button cmdClose;
		private System.Windows.Forms.Button cmdDecode;
		
		public Radix64Decoder() {
			InitializeComponent();
			
			cmdClose.Click += new EventHandler(cmdClose_Click);
			cmdDecode.Click += new EventHandler(cmdDecode_Click);
		}
		
		void InitializeComponent() {
			this.cmdDecode = new System.Windows.Forms.Button();
			this.cmdClose = new System.Windows.Forms.Button();
			this.label2 = new System.Windows.Forms.Label();
			this.txtPlaintext = new System.Windows.Forms.TextBox();
			this.label = new System.Windows.Forms.Label();
			this.txtRadix64 = new System.Windows.Forms.TextBox();
			this.SuspendLayout();
			// 
			// cmdDecode
			// 
			this.cmdDecode.Location = new System.Drawing.Point(376, 312);
			this.cmdDecode.Name = "cmdDecode";
			this.cmdDecode.Size = new System.Drawing.Size(96, 24);
			this.cmdDecode.TabIndex = 5;
			this.cmdDecode.Text = "Decode";
			// 
			// cmdClose
			// 
			this.cmdClose.Location = new System.Drawing.Point(480, 312);
			this.cmdClose.Name = "cmdClose";
			this.cmdClose.Size = new System.Drawing.Size(96, 24);
			this.cmdClose.TabIndex = 4;
			this.cmdClose.Text = "Close";
			// 
			// label2
			// 
			this.label2.Location = new System.Drawing.Point(296, 8);
			this.label2.Name = "label2";
			this.label2.Size = new System.Drawing.Size(168, 16);
			this.label2.TabIndex = 3;
			this.label2.Text = "Decoded Plaintext";
			// 
			// txtPlaintext
			// 
			this.txtPlaintext.Location = new System.Drawing.Point(296, 24);
			this.txtPlaintext.Multiline = true;
			this.txtPlaintext.Name = "txtPlaintext";
			this.txtPlaintext.Size = new System.Drawing.Size(280, 280);
			this.txtPlaintext.TabIndex = 2;
			this.txtPlaintext.Text = "";
			// 
			// label
			// 
			this.label.Location = new System.Drawing.Point(8, 8);
			this.label.Name = "label";
			this.label.Size = new System.Drawing.Size(272, 16);
			this.label.TabIndex = 1;
			this.label.Text = "Radix64 Encoded";
			// 
			// txtRadix64
			// 
			this.txtRadix64.Location = new System.Drawing.Point(8, 24);
			this.txtRadix64.Multiline = true;
			this.txtRadix64.Name = "txtRadix64";
			this.txtRadix64.Size = new System.Drawing.Size(280, 280);
			this.txtRadix64.TabIndex = 0;
			this.txtRadix64.Text = "";
			// 
			// frmRadix64Decoder
			// 
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.ClientSize = new System.Drawing.Size(584, 341);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.cmdDecode,
						this.cmdClose,
						this.label2,
						this.txtPlaintext,
						this.label,
						this.txtRadix64});
			this.Name = "frmRadix64Decoder";
			this.ResumeLayout(false);
		}
		
		void cmdClose_Click(Object sender, System.EventArgs e) {
			this.Hide();
		}
		
		void cmdDecode_Click(Object sender, System.EventArgs e) {
			byte[] bPlaintext = Radix64.Decode(txtRadix64.Text);
			string strOutput = "";
			
			for (int i=0; i<bPlaintext.Length; i++) {
				strOutput += bPlaintext[i].ToString() + ":";
			}
			
			this.txtPlaintext.Text = strOutput;
			
			PublicKeyRing pkpRing = new PublicKeyRing();
			pkpRing.Load("C:\\keyring.txt");
			pkpRing.Save("C:\\keyringout.txt");
		}
		
	}
}

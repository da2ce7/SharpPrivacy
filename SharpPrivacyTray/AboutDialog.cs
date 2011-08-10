//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// AboutDialog.cs: 
// 	Displays readme.rtf in the about box.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 26.05.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;

namespace SharpPrivacy.SharpPrivacyTray {
	public class AboutDialog : System.Windows.Forms.Form {
		System.Windows.Forms.RichTextBox rtbAbout;
		
		public AboutDialog() {
			InitializeMyComponent();
		}
		
		// THIS METHOD IS MAINTAINED BY THE FORM DESIGNER
		// DO NOT EDIT IT MANUALLY! YOUR CHANGES ARE LIKELY TO BE LOST
		void InitializeMyComponent() {
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", System.Reflection.Assembly.GetExecutingAssembly()); 
			this.Icon = (System.Drawing.Icon)resources.GetObject("menuAbout");
			
			this.rtbAbout = new System.Windows.Forms.RichTextBox();
			this.SuspendLayout();
			
			//
			// rtbAbout
			//
			rtbAbout.Dock = DockStyle.Fill;
			rtbAbout.DetectUrls = true;
			rtbAbout.LoadFile(Application.StartupPath + "/readme.rtf");
			rtbAbout.ReadOnly = true;
			rtbAbout.LinkClicked += new LinkClickedEventHandler(this.rtbAbout_LinkClicked);
			// 
			// CreatedForm
			// 
			this.ClientSize = new System.Drawing.Size(520, 309);
			this.Text = "About SharpPrivacy...";
			this.Controls.Add(rtbAbout);
			this.ResumeLayout(false);
		}
		
		void rtbAbout_LinkClicked(object sender, LinkClickedEventArgs e) {
			System.Diagnostics.Process.Start(e.LinkText);
		}
	}
}

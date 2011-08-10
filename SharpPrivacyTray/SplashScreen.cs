//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SplashScreen.cs: 
// 	Displays a splash screen.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
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

namespace SharpPrivacy.SharpPrivacyTray {
	/// <summary>
	/// Summary description for SplashScreen.
	/// </summary>
	public class SplashScreen : System.Windows.Forms.Form {
		private System.Windows.Forms.PictureBox pictureBox1;

		public SplashScreen() {
			//
			// Required for Windows Form Designer support
			//
			InitializeComponent();
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent() {
			this.pictureBox1 = new System.Windows.Forms.PictureBox();
			this.SuspendLayout();
			
			// 
			// pictureBox1
			// 
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", System.Reflection.Assembly.GetExecutingAssembly()); 
			this.pictureBox1.Image = (Bitmap)resources.GetObject("splashScreen");
			this.pictureBox1.Name = "pictureBox1";
			this.pictureBox1.Size = new System.Drawing.Size(450, 250);
			this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
			this.pictureBox1.TabIndex = 0;
			this.pictureBox1.TabStop = false;
			// 
			// SplashScreen
			// 
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.BackColor = System.Drawing.Color.White;
			this.ClientSize = new System.Drawing.Size(450, 250);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
																		  this.pictureBox1});
			this.StartPosition = FormStartPosition.CenterScreen;
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
			this.ShowInTaskbar = false;
			this.Name = "SplashScreen";
			this.Text = "SplashScreen";
			this.ResumeLayout(false);

		}
		#endregion
	}
}

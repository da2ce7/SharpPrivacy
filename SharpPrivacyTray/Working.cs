//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// Working.cs: 
// 	GUI for showing that the program is currently working.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 02.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;
using System.Drawing;

namespace SharpPrivacy.SharpPrivacyTray {
	public class Working : System.Windows.Forms.Form {
		private System.Windows.Forms.Label label;
		private System.Windows.Forms.Button cmdCancel;
		private System.Drawing.Bitmap bmpWait = new Bitmap("working.gif");
		
		public Working() {
			InitializeComponent();
			
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", System.Reflection.Assembly.GetExecutingAssembly());
			
			this.Icon = (System.Drawing.Icon)resources.GetObject("iconWorking");
			Application.DoEvents();
			bmpWait.MakeTransparent();
			
			AnimateImage();
		}
		
		private void AnimateImage() {
			ImageAnimator.Animate(bmpWait, new EventHandler(this.OnFrameChanged));
		}
		
		private void OnFrameChanged(object o, EventArgs e) {
			this.Invalidate();
		}
		
		protected override void OnPaint(PaintEventArgs e) {
			
			ImageAnimator.UpdateFrames();
			
			e.Graphics.DrawImage(this.bmpWait, new Point(20,28));
			base.OnPaint(e);
		}
		
		private void InitializeComponent() {
			this.cmdCancel = new System.Windows.Forms.Button();
			this.label = new System.Windows.Forms.Label();
			this.SuspendLayout();
			// 
			// cmdCancel
			// 
			this.cmdCancel.Enabled = false;
			this.cmdCancel.Location = new System.Drawing.Point(204, 89);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(88, 24);
			this.cmdCancel.TabIndex = 3;
			this.cmdCancel.Text = "Cancel";
			// 
			// label
			// 
			this.label.Location = new System.Drawing.Point(16, 8);
			this.label.Name = "label";
			this.label.Size = new System.Drawing.Size(264, 16);
			this.label.TabIndex = 1;
			this.label.Text = "Please allow a second for the action to be taken...";
			// 
			// Working
			// 
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 14);
			this.ClientSize = new System.Drawing.Size(296, 117);
			this.Controls.Add(this.cmdCancel);
			this.Controls.Add(this.label);
			this.Name = "Working";
			this.ShowInTaskbar = false;
			this.Text = "Please wait...";
			this.ResumeLayout(false);
		}
	}
}


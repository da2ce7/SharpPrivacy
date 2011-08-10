//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// ImageMenuItem.cs: 
//	Add Images beneath menu items
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.2.0
//
// Changelog:
//	- 13.06.2004: Created this file.
//
// (C) 2004, Daniel Fabian
//

using System;
using System.Reflection;
using System.Drawing;
using System.Drawing.Text;
using System.Windows.Forms;

namespace SharpPrivacy.SharpPrivacyTray {
	
	/// <summary>
	/// TODO - Add class summary
	/// </summary>
	/// <remarks>
	/// 	created by - df
	/// 	created on - 13.06.2004 16:15:38
	/// </remarks>
	public class ImageMenuItem : System.Windows.Forms.MenuItem {
		private Icon icon;
		private Font font;
		
		public Icon Icon {
			get {
				return icon;
			}
			set {
				icon = value;
			}
		}
		
		public ImageMenuItem(string text) : base(text) {
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", Assembly.GetExecutingAssembly()); 
			Icon blank = (Icon)resources.GetObject("menuBlank");
			makeReady(blank);
		}
		
		public ImageMenuItem(Icon icon) : this(icon, "") {}
		
		public ImageMenuItem(Icon icon, string text) : base(text) {
			makeReady(icon);
		}
		
		public ImageMenuItem(Icon icon, string text, EventHandler onClick) : base(text, onClick) {
			makeReady(icon);
		}
		
		public ImageMenuItem(Icon icon, string text, MenuItem[] items) : base(text, items) {
			makeReady(icon);
		}
		
		public ImageMenuItem(Icon icon, string text, EventHandler onClick, Shortcut shortcut) : base(text, onClick, shortcut) {
			makeReady(icon);
		}
		
		public ImageMenuItem(Icon icon, MenuMerge mergeType, int mergeOrder, Shortcut shortcut, string text, EventHandler onClick, EventHandler onPopup, EventHandler onSelect, MenuItem[] items) : base(mergeType, mergeOrder, shortcut, text, onClick, onPopup, onSelect, items) {
			makeReady(icon);
		}
		
		private void makeReady(Icon icon) {
			this.OwnerDraw = true;
			this.font = SystemInformation.MenuFont;
			this.icon = icon;
			// this.OnMeasureItem += new Meas
		}
		
		protected override void OnMeasureItem(MeasureItemEventArgs e) {
			base.OnMeasureItem(e);
			
			StringFormat sf = new StringFormat();
			
			sf.HotkeyPrefix = HotkeyPrefix.Show;
			sf.SetTabStops(50, new Single[] {0});
			
			if (icon.Height > font.Height) {
				e.ItemHeight = icon.Height + 3;
			} else {
				e.ItemHeight = font.Height + 3;
			}
			
			e.ItemWidth = (int)((e.Graphics.MeasureString(AppendShortcut(), font, 1000, sf).Width) + icon.Width + 5);
			sf.Dispose();
		}
		
		protected override void OnDrawItem(DrawItemEventArgs e) {
			Brush br = new SolidBrush(SystemColors.WindowText);

			StringFormat sf;
			
			base.OnDrawItem(e);
			e.Graphics.FillRectangle(SystemBrushes.Control, e.Bounds);
			
			bool menuSelected = (e.State & DrawItemState.Selected) > 0;
			if (menuSelected) {
				int x = e.Bounds.Left + this.icon.Width + 8;
				int y = e.Bounds.Top + 1;
				e.Graphics.FillRectangle(SystemBrushes.Highlight, e.Bounds);
				br = new SolidBrush(SystemColors.HighlightText);
			}
			
			if (this.icon != null) {
				e.Graphics.DrawIcon(this.icon, e.Bounds.Left + 3, e.Bounds.Top + 3);
			}
			
			sf = new StringFormat();
			sf.HotkeyPrefix = HotkeyPrefix.Show;
			sf.SetTabStops(50, new Single[] {0});
			e.Graphics.DrawString(AppendShortcut(), this.font, br, e.Bounds.Left + this.icon.Width + 10, e.Bounds.Top + 2, sf);

			br.Dispose();
			sf.Dispose();
		}
		
		private string AppendShortcut() {
			String s;
			s = this.Text;
			
			if (this.ShowShortcut && (this.Shortcut != Shortcut.None)) {
				Keys k = (Keys)Shortcut;
				s = s + Convert.ToChar(9) + System.ComponentModel.TypeDescriptor.GetConverter(k.GetType()).ConvertToString(k);
			}
			return s;
		}
		
		
	}
}

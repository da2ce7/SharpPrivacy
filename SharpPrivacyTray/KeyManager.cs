//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// KeyManager.cs: 
// 	GUI Key Manager for administering the keyrings
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.2.0
//
// Changelog:
//	- 29.12.2002: Created this file
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace to SharpPrivacy.SharpPrivacyTray
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Windows.Forms;
using System.Collections;
using System.Drawing;
using SynapticEffect.Forms;
using System.Reflection;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	public class KeyManager : System.Windows.Forms.Form {
		private System.ComponentModel.IContainer components;
		private System.Windows.Forms.ImageList imglTreeListView;
		private System.Windows.Forms.ImageList imglToolbar;
		private System.Windows.Forms.ToolBar tlbToolbar;
		private System.Windows.Forms.StatusBar stbStatus;
		private SynapticEffect.Forms.TreeListView tlvKeys;
		
		private ToggleColumnHeader tchKeys;
		private ToggleColumnHeader tchTrust;
		private ToggleColumnHeader tchSize;
		private ToggleColumnHeader tchDescription;
		private ToggleColumnHeader tchKeyID;
		private ToggleColumnHeader tchCreation;
		private ToggleColumnHeader tchExpiration;
		private ToggleColumnHeader tchAlgorithm;
		
		private ToolBarButton tbbNewKeyPair;
		private ToolBarButton tbbCopy;
		private ToolBarButton tbbPaste;
		private ToolBarButton tbbDelete;
		
		private ContextMenu cmKeyMenu = new ContextMenu();
		
		private ImageMenuItem mnuKeyMenuCopy = new ImageMenuItem("Copy");
		private ImageMenuItem mnuKeyMenuPaste = new ImageMenuItem("Paste");
		private ImageMenuItem mnuKeyMenuDelete = new ImageMenuItem("Delete");
		private MenuItem mnuKeyMenuSep1 = new MenuItem("-");
		private ImageMenuItem mnuKeyMenuAdd = new ImageMenuItem("Add");
		private ImageMenuItem mnuKeyMenuAddID = new ImageMenuItem("UserID");
		private ImageMenuItem mnuKeyMenuAddSignature = new ImageMenuItem("Signature");
		private ImageMenuItem mnuKeyMenuProperties = new ImageMenuItem("Properties");
		
		
		private MainMenu mnuMainMenu = new MainMenu();
		
		private MenuItem mnuFile = new MenuItem("File");
		private ImageMenuItem mnuFileOpen = new ImageMenuItem("Open...");
		private ImageMenuItem mnuFileNew = new ImageMenuItem("New...");
		private MenuItem mnuFileSeperator1 = new MenuItem("-");
		private ImageMenuItem mnuFileExit = new ImageMenuItem("Exit");
		
		private MenuItem mnuEdit = new MenuItem("Edit");
		private ImageMenuItem mnuEditCopy = new ImageMenuItem("Copy");
		private ImageMenuItem mnuEditPaste = new ImageMenuItem("Paste");
		private ImageMenuItem mnuEditDelete = new ImageMenuItem("Delete");
		private MenuItem mnuEditSeperator1 = new MenuItem("-");
		private ImageMenuItem mnuEditSelectAll = new ImageMenuItem("Select All");
		private ImageMenuItem mnuEditCollapseSelection = new ImageMenuItem("Collapse Selection");
		private ImageMenuItem mnuEditExpandSelection = new ImageMenuItem("Expand Selection");
		private MenuItem mnuEditSeperator2 = new MenuItem("-");
		private ImageMenuItem mnuEditOptions = new ImageMenuItem("Options...");
		
		private MenuItem mnuKeys = new MenuItem("Keys");
		private ImageMenuItem mnuKeysNewKey = new ImageMenuItem("New Key...");
		private ImageMenuItem mnuKeysRefresh = new ImageMenuItem("Refresh");
		
		public KeyManager() {
			InitializeComponent();
			InitializeMyComponents();
			LoadKeys();
		}
		
		void AddKey(XmlElement xmlKey) {
			if (xmlKey.Name == "SecretKey")
				AddSecretKey(xmlKey);
			
			if (xmlKey.Name == "PublicKey")
				AddPublicKey(xmlKey);
		}
		
		void AddPublicKey(XmlElement xmlKey) {
			// A sample Xml Public Key
			// <PublicKey keyid="0x518ad7fa1bc9ebc1" fingerprint="E8617C691842CD9FE8EE5876518AD7FA1BC9EBC1" created="631844810390000000" expiration="never" size="1024" algorithm="DSA">
			// 	<UserIDs>
			// 		<UserID name="Max Mustermann <max@mustermann.de>" primary="true" created="631844810390000000">
			// 			<Signature keyid="0x518ad7fa1bc9ebc1" created="631844810390000000" expiration="never" signaturestatus="Valid" /> 
			// 		</UserID>
			// 	</UserIDs>
			// 	<Subkeys>
			// 		<Subkey keyid="0xd2cd461cb79ef4b9" fingerprint="5BE02F4B0D53334254762124D2CD461CB79EF4B9" created="631844810450000000" expiration="never" size="2048" algorithm="ElGamal_Encrypt_Only" /> 
			// 	</Subkeys>
			// </PublicKey>	
			string strKeyID = xmlKey.GetAttribute("keyid");
			string strFingerPrint = xmlKey.GetAttribute("fingerprint");
			string strTimeCreated = xmlKey.GetAttribute("created");
			DateTime dtTimeCreated = new DateTime(Int64.Parse(strTimeCreated));
			strTimeCreated = dtTimeCreated.ToString();
			string strExpiration = xmlKey.GetAttribute("expiration");
			if (strExpiration != "never") {
				DateTime dtExpiration = new DateTime(Int64.Parse(strExpiration));
				strExpiration = dtExpiration.ToString();
			}
			string strSize = xmlKey.GetAttribute("size");
			string strAlgorithm = xmlKey.GetAttribute("algorithm");
			
			XmlNodeList xnlSubkeys = xmlKey.GetElementsByTagName("Subkey");
			IEnumerator ieSubkeys = xnlSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				XmlElement xmlSubkey = (XmlElement)ieSubkeys.Current;
				
				strSize += "/" + xmlSubkey.GetAttribute("size");
				strAlgorithm += "/" + xmlSubkey.GetAttribute("algorithm");
			}
			string strTrust = "*****";
			
			TreeListNode tlnItem = new TreeListNode();
			
			tlnItem.ImageIndex = 0;
			tlnItem.SubItems.Add(strTrust);
			tlnItem.SubItems.Add(strSize);
			tlnItem.SubItems.Add("Public Key");
			tlnItem.SubItems.Add(strKeyID);
			tlnItem.SubItems.Add(strTimeCreated);
			tlnItem.SubItems.Add(strExpiration);
			tlnItem.SubItems.Add(strAlgorithm);
			tlnItem.Tag = xmlKey;
			
			// Add UserIDs
			XmlNodeList xnlUserIDs = xmlKey.GetElementsByTagName("UserID");
			IEnumerator ieUserIDs = xnlUserIDs.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				XmlElement xmlUserID = (XmlElement)ieUserIDs.Current;
				
				TreeListNode tlnUserID = new TreeListNode();
				
				string strName = xmlUserID.GetAttribute("name");
				string strCreated = xmlUserID.GetAttribute("created");
				string strPrimary = xmlUserID.GetAttribute("primary");
				if (strPrimary == "true")
					tlnItem.Text = strName;

				DateTime dtCreated = new DateTime(Int64.Parse(strCreated));
				strCreated = dtCreated.ToString();
				
				tlnUserID.ImageIndex = 1;
				tlnUserID.Text = strName;
				tlnUserID.SubItems.Add(strTrust);
				tlnUserID.SubItems.Add(""); // size
				tlnUserID.SubItems.Add("User ID");
				tlnUserID.SubItems.Add(""); // key id
				tlnUserID.SubItems.Add(strCreated);
				tlnUserID.SubItems.Add(""); // expiration
				tlnUserID.SubItems.Add(""); // algorithm
				
				XmlNodeList xnlSignatures = xmlUserID.GetElementsByTagName("Signature");
				IEnumerator ieSignatures = xnlSignatures.GetEnumerator();
				while (ieSignatures.MoveNext()) {
					XmlElement xmlSignature = (XmlElement)ieSignatures.Current;
					
					TreeListNode tlnSignature = new TreeListNode();
					
					string strCreator = xmlSignature.GetAttribute("creator");
					strKeyID = xmlSignature.GetAttribute("keyid");
					string strSignatureStatus = xmlSignature.GetAttribute("signaturestatus");
					strCreated = xmlSignature.GetAttribute("created");
					dtCreated = new DateTime(Int64.Parse(strCreated));
					strCreated = dtCreated.ToString();
					strAlgorithm = xmlSignature.GetAttribute("algorithm");
					strExpiration = xmlSignature.GetAttribute("expiration");
					
					tlnSignature.ImageIndex = 2;
					tlnSignature.Text = strCreator;
					if (strSignatureStatus != "Valid") {
						//TODO: Make Signature that are not valid italic (that rymes :)
						//tlnSignature.Font = new System.Drawing.Font(tlnSignature.Font, FontStyle.Italic);
					}
					tlnSignature.SubItems.Add(""); // trust
					tlnSignature.SubItems.Add(""); // size
					tlnSignature.SubItems.Add(strSignatureStatus + " Signature");
					tlnSignature.SubItems.Add(strKeyID);
					tlnSignature.SubItems.Add(strCreated);
					tlnSignature.SubItems.Add(strExpiration); // expiration
					tlnSignature.SubItems.Add(strAlgorithm); // algorithm
					
					tlnUserID.Nodes.Add(tlnSignature);
				}
				
				tlnItem.Nodes.Add(tlnUserID);
			}
			this.tlvKeys.Nodes.Add(tlnItem);
		}
		
		void AddSecretKey(XmlElement xmlKey) {
			// A sample xml secret key
			// <SecretKey keyid="0x2d388aee0c3ee61a" fingerprint="121EA091A3192720A64B37EB2D388AEE0C3EE61A" size="1024" algorithm="DSA">
			// 	<UserIDs>
			// 		<UserID name="Max Mustermann AES <max@mustermann.aes>" /> 
			// 	</UserIDs>
			// 	<Subkeys>
			// 		<Subkey keyid="0x3d50aae3e4ffe8fa" fingerprint="B964375E4C756AD6EED60AA23D50AAE3E4FFE8FA" size="2048" algorithm="ElGamal_Encrypt_Only" /> 
			// 	</Subkeys>
			// </SecretKey>			
			TreeListNode tlnItem = new TreeListNode();
			
			string strSize = xmlKey.GetAttribute("size");
			string strKeyID = xmlKey.GetAttribute("keyid");
			string strAlgorithm = xmlKey.GetAttribute("algorithm");
			string strTimeCreated = xmlKey.GetAttribute("timecreated");
			DateTime dtTimeCreated = new DateTime(Int64.Parse(strTimeCreated));
			strTimeCreated = dtTimeCreated.ToString();
			
			XmlNodeList xnlSubkeys = xmlKey.GetElementsByTagName("Subkey");
			IEnumerator ieSubkeys = xnlSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				XmlElement xmlSubkey = (XmlElement)ieSubkeys.Current;
				
				strSize += "/" + xmlSubkey.GetAttribute("size");
				strAlgorithm += "/" + xmlSubkey.GetAttribute("algorithm");
			}
			
			tlnItem.SubItems.Add("*****"); // trust
			tlnItem.SubItems.Add(strSize);
			tlnItem.SubItems.Add("Secret Key");
			tlnItem.SubItems.Add(strKeyID);
			tlnItem.SubItems.Add(strTimeCreated);
			tlnItem.SubItems.Add("");
			tlnItem.SubItems.Add(strAlgorithm);
			tlnItem.Tag = xmlKey;
			
			XmlNodeList xnlUserIDs = xmlKey.GetElementsByTagName("UserID");
			IEnumerator ieUserIDs = xnlUserIDs.GetEnumerator();
			tlnItem.Text = ((XmlElement)xnlUserIDs.Item(0)).GetAttribute("name");
			while (ieUserIDs.MoveNext()) {
				XmlElement xmlUserID = (XmlElement)ieUserIDs.Current;
				
				TreeListNode tlnUserID = new TreeListNode();
				
				string strName = xmlUserID.GetAttribute("name");
				
				tlnUserID.Text = strName;
				tlnUserID.SubItems.Add(""); // trust
				tlnUserID.SubItems.Add(""); // size
				tlnUserID.SubItems.Add("UserID"); // description
				tlnUserID.SubItems.Add(""); // keyid
				tlnUserID.SubItems.Add(""); // creation
				tlnUserID.SubItems.Add(""); // expiration
				tlnUserID.SubItems.Add(""); // algorithm
				
				tlnUserID.ImageIndex = 1;
				
				tlnItem.Nodes.Add(tlnUserID);
			}
			
			tlnItem.ImageIndex = 3;
			tlnItem.Tag = xmlKey;
			this.tlvKeys.Nodes.Add(tlnItem);
		}
		
		void LoadKeys() {
			this.tlvKeys.Nodes.Clear();
			XmlNodeList xnlSecretKeys = SharpPrivacy.SecretKeyRing.GetElementsByTagName("SecretKey");
			IEnumerator ieKeys = xnlSecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				XmlElement xmlKey = (XmlElement)ieKeys.Current;
				
				try {
					AddKey(xmlKey);
				} catch (Exception e) {
					DialogResult drResult = MessageBox.Show("Could not add a secret key : " + e.Message + "\nDo you want to remove the key from your local keyring?", "Error...", MessageBoxButtons.YesNo, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					if (drResult == DialogResult.Yes) {
						try {
							string strKeyID = xmlKey.GetAttribute("keyid");
							ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
							SharpPrivacy.Instance.RemoveSecretKey(lKeyID);
						} catch (Exception ee) {
							MessageBox.Show("Deleting the key failed: " + ee.Message + "\nYou must delete the key directly from your keyring file", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
						}
					}
				}
			}
			
			XmlNodeList xnlPublicKeys = SharpPrivacy.PublicKeyRing.GetElementsByTagName("PublicKey");
			ieKeys = xnlPublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				XmlElement xmlKey = (XmlElement)ieKeys.Current;
				try {
					AddKey(xmlKey);
				} catch (Exception e) {
					DialogResult drResult = MessageBox.Show("Could not add a public key: " + e.Message + "\nDo you want to remove the key from your local keyring?", "Error...", MessageBoxButtons.YesNo, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					if (drResult == DialogResult.Yes) {
						try {
							string strKeyID = xmlKey.GetAttribute("keyid");
							ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
							SharpPrivacy.Instance.RemovePublicKey(lKeyID);
						} catch (Exception ee) {
							MessageBox.Show("Deleting the key failed: " + ee.Message + "\nYou must delete the key directly from your keyring file", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
						}
					}
				}
			}
		}
		
		void InitializeMyComponents() {
			this.SuspendLayout();
			
			this.mnuFileExit.Click += new EventHandler(this.mnuFileExit_Click);
			this.mnuKeysNewKey.Click += new EventHandler(this.mnuKeysNewKey_Click);
			this.mnuEditCollapseSelection.Click += new EventHandler(this.mnuEditCollapseSelection_Click);
			this.mnuEditExpandSelection.Click += new EventHandler(this.mnuEditExpandSelection_Click);
			this.mnuKeyMenuCopy.Click += new EventHandler(this.mnuKeyMenuCopy_Click);
			this.mnuKeyMenuPaste.Click += new EventHandler(this.mnuKeyMenuPaste_Click);
			this.mnuKeyMenuDelete.Click += new EventHandler(this.mnuKeyMenuDelete_Click);
			this.mnuKeyMenuAddSignature.Click += new EventHandler(this.mnuKeyMenuAddSignature_Click);
			this.mnuKeyMenuAddID.Click += new EventHandler(this.mnuKeyMenuAddID_Click);
			this.mnuEditCopy.Click += new EventHandler(this.mnuEditCopy_Click);
			this.mnuEditDelete.Click += new EventHandler(this.mnuEditDelete_Click);
			this.mnuEditPaste.Click += new EventHandler(this.mnuEditPaste_Click);
			this.mnuEditSelectAll.Click += new EventHandler(this.mnuEditSelectAll_Click);
			this.mnuKeysRefresh.Click += new EventHandler(this.mnuKeysRefresh_Click);
			this.mnuKeyMenuProperties.Click += new EventHandler(this.mnuKeyMenuProperties_Click);
			this.tlbToolbar.ButtonClick += new ToolBarButtonClickEventHandler(this.tlbToolbar_Click);
			this.Resize += new System.EventHandler(this.KeyManager_Resize);
			
			// Key menu (popupmenu when key is right-clicked);
			this.mnuKeyMenuAdd.MenuItems.Add(this.mnuKeyMenuAddID);
			this.mnuKeyMenuAdd.MenuItems.Add(this.mnuKeyMenuAddSignature);
			
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuCopy);
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuPaste);
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuDelete);
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuSep1);
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuAdd);
			this.cmKeyMenu.MenuItems.Add(this.mnuKeyMenuProperties);
			
			
			// Main menu
			this.mnuFileOpen.Visible = false;
			this.mnuFileNew.Visible = false;
			this.mnuFileSeperator1.Visible = false;
			this.mnuFile.MenuItems.Add(this.mnuFileOpen);
			this.mnuFile.MenuItems.Add(this.mnuFileNew);
			this.mnuFile.MenuItems.Add(this.mnuFileSeperator1);
			this.mnuFile.MenuItems.Add(this.mnuFileExit);
			
			
			this.mnuEditOptions.Visible = false;
			this.mnuEdit.MenuItems.Add(this.mnuEditCopy);
			this.mnuEdit.MenuItems.Add(this.mnuEditPaste);
			this.mnuEdit.MenuItems.Add(this.mnuEditDelete);
			this.mnuEdit.MenuItems.Add(this.mnuEditSeperator1);
			this.mnuEdit.MenuItems.Add(this.mnuEditSelectAll);
			this.mnuEdit.MenuItems.Add(this.mnuEditCollapseSelection);
			this.mnuEdit.MenuItems.Add(this.mnuEditExpandSelection);
			this.mnuEdit.MenuItems.Add(this.mnuEditSeperator2);
			this.mnuEdit.MenuItems.Add(this.mnuEditOptions);
			
			this.mnuKeys.MenuItems.Add(this.mnuKeysNewKey);
			this.mnuKeys.MenuItems.Add(this.mnuKeysRefresh);
			
			this.mnuMainMenu.MenuItems.Add(this.mnuFile);
			this.mnuMainMenu.MenuItems.Add(this.mnuEdit);
			this.mnuMainMenu.MenuItems.Add(this.mnuKeys);
			
			this.tbbNewKeyPair = new ToolBarButton("New Key Pair");
			this.tbbNewKeyPair.ImageIndex = 0;
			this.tbbCopy = new ToolBarButton("Copy");
			this.tbbCopy.ImageIndex = 1;
			this.tbbPaste = new ToolBarButton("Paste");
			this.tbbPaste.ImageIndex = 2;
			this.tbbDelete = new ToolBarButton("Delete");
			this.tbbDelete.ImageIndex = 3;
			
			this.tlbToolbar.Buttons.Add(tbbNewKeyPair);
			this.tlbToolbar.Buttons.Add(tbbCopy);
			this.tlbToolbar.Buttons.Add(tbbPaste);
			this.tlbToolbar.Buttons.Add(tbbDelete);
			this.tlbToolbar.Appearance = ToolBarAppearance.Flat;
			this.tlbToolbar.ButtonSize = new System.Drawing.Size(16, 16);
			
			this.tchKeys = new ToggleColumnHeader();
			this.tchKeys.Hovered = false;
			this.tchKeys.Index = 0;
			this.tchKeys.Pressed = false;
			this.tchKeys.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchKeys.Selected = false;
			this.tchKeys.Text = "Keys";
			this.tchKeys.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchKeys.Visible = true;
			this.tchKeys.Width = 300;
			
			this.tchTrust = new ToggleColumnHeader();
			this.tchTrust.Hovered = false;
			this.tchTrust.Index = 2;
			this.tchTrust.Pressed = false;
			this.tchTrust.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchTrust.Selected = false;
			this.tchTrust.Text = "Trust";
			this.tchTrust.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchTrust.Visible = true;
			this.tchTrust.Width = 60;
			
			this.tchSize = new ToggleColumnHeader();
			this.tchSize.Hovered = false;
			this.tchSize.Index = 3;
			this.tchSize.Pressed = false;
			this.tchSize.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchSize.Selected = false;
			this.tchSize.Text = "Size";
			this.tchSize.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchSize.Visible = true;
			this.tchSize.Width = 50;
			
			this.tchDescription = new ToggleColumnHeader();
			this.tchDescription.Hovered = false;
			this.tchDescription.Index = 4;
			this.tchDescription.Pressed = false;
			this.tchDescription.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchDescription.Selected = false;
			this.tchDescription.Text = "Description";
			this.tchDescription.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchDescription.Visible = true;
			this.tchDescription.Width = 120;

			this.tchKeyID = new ToggleColumnHeader();
			this.tchKeyID.Hovered = false;
			this.tchKeyID.Index = 5;
			this.tchKeyID.Pressed = false;
			this.tchKeyID.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchKeyID.Selected = false;
			this.tchKeyID.Text = "Key ID";
			this.tchKeyID.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchKeyID.Visible = true;
			this.tchKeyID.Width = 100;

			this.tchCreation = new ToggleColumnHeader();
			this.tchCreation.Hovered = false;
			this.tchCreation.Index = 6;
			this.tchCreation.Pressed = false;
			this.tchCreation.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchCreation.Selected = false;
			this.tchCreation.Text = "Creation";
			this.tchCreation.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchCreation.Visible = true;
			this.tchCreation.Width = 120;

			this.tchExpiration = new ToggleColumnHeader();
			this.tchExpiration.Hovered = false;
			this.tchExpiration.Index = 7;
			this.tchExpiration.Pressed = false;
			this.tchExpiration.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchExpiration.Selected = false;
			this.tchExpiration.Text = "Expiration";
			this.tchExpiration.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchExpiration.Visible = true;
			this.tchExpiration.Width = 120;

			this.tchAlgorithm = new ToggleColumnHeader();
			this.tchAlgorithm.Hovered = false;
			this.tchAlgorithm.Index = 7;
			this.tchAlgorithm.Pressed = false;
			this.tchAlgorithm.ScaleStyle = SynapticEffect.Forms.ColumnScaleStyle.Slide;
			this.tchAlgorithm.Selected = false;
			this.tchAlgorithm.Text = "Algorithm";
			this.tchAlgorithm.TextAlign = System.Windows.Forms.HorizontalAlignment.Left;
			this.tchAlgorithm.Visible = true;
			this.tchAlgorithm.Width = 60;
			
			this.tlvKeys = new TreeListView();
			this.tlvKeys.ContextMenu = cmKeyMenu;
			this.tlvKeys.HeaderMenu = null;
			this.tlvKeys.ItemMenu = null;
			this.tlvKeys.MultiSelect = true;
			this.tlvKeys.Dock = System.Windows.Forms.DockStyle.None;
			this.tlvKeys.Left = 0;
			this.tlvKeys.Top = 45;
			this.tlvKeys.Size = new System.Drawing.Size(this.Width, this.Height-120);
			this.tlvKeys.Name = "tlvKeys";
			this.tlvKeys.ShowLines = true;
			
			this.tlvKeys.Columns.Add(this.tchKeys);
			this.tlvKeys.Columns.Add(this.tchTrust);
			this.tlvKeys.Columns.Add(this.tchSize);
			this.tlvKeys.Columns.Add(this.tchDescription);
			this.tlvKeys.Columns.Add(this.tchKeyID);
			this.tlvKeys.Columns.Add(this.tchCreation);
			this.tlvKeys.Columns.Add(this.tchExpiration);
			this.tlvKeys.Columns.Add(this.tchAlgorithm);
			this.tlvKeys.SmallImageList = imglTreeListView;
			this.Controls.Add(this.tlvKeys);
			//this.tlvKeys.MouseUp += new MouseEventHandler(this.tlvKeys_MouseUp);
			
			System.Resources.ResourceManager resources = new System.Resources.ResourceManager("SharpPrivacyTray", Assembly.GetExecutingAssembly()); 
			
			this.imglToolbar.Images.Add((Icon)resources.GetObject("menuKeyPair"));
			this.imglToolbar.Images.Add((Icon)resources.GetObject("menuCopy"));
			this.imglToolbar.Images.Add((Icon)resources.GetObject("menuPaste"));
			this.imglToolbar.Images.Add((Icon)resources.GetObject("menuDelete"));
			
			this.imglTreeListView.Images.Add((Icon)resources.GetObject("listPublicKey"));
			this.imglTreeListView.Images.Add((Icon)resources.GetObject("listUserID"));
			this.imglTreeListView.Images.Add((Icon)resources.GetObject("listSignature"));
			this.imglTreeListView.Images.Add((Icon)resources.GetObject("listSecretKey"));
			
			this.mnuEditCopy.Icon = ((Icon)resources.GetObject("menuCopy"));
			this.mnuEditPaste.Icon = ((Icon)resources.GetObject("menuPaste"));
			this.mnuEditDelete.Icon = ((Icon)resources.GetObject("menuDelete"));
			
			this.mnuKeyMenuAddSignature.Icon = ((Icon)resources.GetObject("listSignature"));
			this.mnuKeyMenuCopy.Icon = ((Icon)resources.GetObject("menuCopy"));
			this.mnuKeyMenuPaste.Icon = ((Icon)resources.GetObject("menuPaste"));
			this.mnuKeyMenuDelete.Icon = ((Icon)resources.GetObject("menuDelete"));
			
			this.mnuKeysNewKey.Icon = ((Icon)resources.GetObject("menuKeyPair"));
			
			this.Menu = mnuMainMenu;
			
			this.Icon = (Icon)resources.GetObject("menuKeyManager");
			
			this.ResumeLayout(false);
		}
		
		
		
		void InitializeComponent() {
			
			this.components = new System.ComponentModel.Container();
			this.stbStatus = new System.Windows.Forms.StatusBar();
			this.tlbToolbar = new System.Windows.Forms.ToolBar();
			this.imglToolbar = new System.Windows.Forms.ImageList(this.components);
			this.imglToolbar = new System.Windows.Forms.ImageList(this.components);
			this.imglTreeListView = new System.Windows.Forms.ImageList(this.components);
			this.imglTreeListView = new System.Windows.Forms.ImageList(this.components);
			this.SuspendLayout();
			// 
			// stbStatus
			// 
			this.stbStatus.Location = new System.Drawing.Point(0, 251);
			this.stbStatus.Name = "stbStatus";
			this.stbStatus.Size = new System.Drawing.Size(292, 22);
			this.stbStatus.TabIndex = 1;
			this.stbStatus.Text = "Key Manager is ready";
			// 
			// tlbToolbar
			// 
			this.tlbToolbar.Appearance = System.Windows.Forms.ToolBarAppearance.Flat;
			this.tlbToolbar.DropDownArrows = true;
			this.tlbToolbar.ImageList = this.imglToolbar;
			this.tlbToolbar.Name = "tlbToolbar";
			this.tlbToolbar.ShowToolTips = true;
			this.tlbToolbar.Size = new System.Drawing.Size(292, 39);
			this.tlbToolbar.TabIndex = 0;
			// 
			// imglToolbar
			// 
			this.imglToolbar.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
			this.imglToolbar.ImageSize = new System.Drawing.Size(16, 16);
			this.imglToolbar.TransparentColor = System.Drawing.Color.Transparent;
			// 
			// imglTreeListView
			// 
			this.imglTreeListView.ColorDepth = System.Windows.Forms.ColorDepth.Depth32Bit;
			this.imglTreeListView.ImageSize = new System.Drawing.Size(16, 16);
			this.imglTreeListView.TransparentColor = System.Drawing.Color.Transparent;
			// 
			// KeyManager
			// 
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.ClientSize = new System.Drawing.Size(292, 273);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
						this.stbStatus,
						this.tlbToolbar});
			this.Name = "KeyManager";
			this.Text = "Key Manager...";
			this.ResumeLayout(false);
		}
		
		void mnuFileExit_Click(Object sender, System.EventArgs e) {
			this.Hide();
		}
		
		void mnuKeysNewKey_Click(Object sender, System.EventArgs e) {
			GenerateKey gkKey = new GenerateKey();
			gkKey.ShowDialog();
			if (!gkKey.Canceled) {
				this.LoadKeys();
				this.stbStatus.Text = "New keypair generated";
			}
			this.stbStatus.Text = "Keygeneration canceled";
		}
		
		void mnuEditCollapseSelection_Click(Object sender, System.EventArgs e) {
			try {
				IEnumerator ieItem = tlvKeys.SelectedNodes.GetEnumerator();
				while (ieItem.MoveNext()) {
					TreeListNode tlnItem = (TreeListNode)ieItem.Current;
					tlnItem.Collapse();
				}
				tlvKeys.Refresh();
				this.stbStatus.Text = "Selection collapsed";
			} catch (Exception) {}
		}
		
		void mnuEditExpandSelection_Click(Object sender, System.EventArgs e) {
			try {
				IEnumerator ieItem = tlvKeys.SelectedNodes.GetEnumerator();
				while (ieItem.MoveNext()) {
					TreeListNode tlnItem = (TreeListNode)ieItem.Current;
					tlnItem.Expand();
				}
				tlvKeys.Refresh();
				this.stbStatus.Text = "Selection expanded";
			} catch (Exception) {}
		}

		void KeyManager_Resize(Object sender, System.EventArgs e) {
			this.tlvKeys.Width = this.Width - 10;
			this.tlvKeys.Height = this.Height - 120;
		}
		
		void mnuKeyMenuCopy_Click(Object sender, System.EventArgs e) {
			IEnumerator ieItem = tlvKeys.SelectedNodes.GetEnumerator();
			
			string strKey = "";
			while (ieItem.MoveNext()) {
				TreeListNode tlnItem = (TreeListNode)ieItem.Current;
				
				try {
					XmlElement xmlKey = (XmlElement)tlnItem.Tag;
					string strKeyID = xmlKey.GetAttribute("keyid");
					ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
					if (xmlKey.Name == "PublicKey") {
						string strThisKey = SharpPrivacy.Instance.GetPublicKey(lKeyID);
						strKey += strThisKey;
					} else if (xmlKey.Name == "SecretKey") {
						QueryPassphrase qpPassphrase = new QueryPassphrase();
						qpPassphrase.ShowSingleKeyDialog(xmlKey);
						string strPassphrase = qpPassphrase.Passphrase;
						string strThisKey = SharpPrivacy.Instance.GetSecretKey(lKeyID, strPassphrase);
						strKey += strThisKey;
					}
				} catch (Exception ex) {
					MessageBox.Show("An Error occured: " + ex.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
					return;
				}
			}
			if (strKey.Length > 0) {
				Clipboard.SetDataObject(strKey);
				this.stbStatus.Text = "Selection saved in clipboard";
			}
		}
		
		void mnuKeyMenuPaste_Click(Object sender, System.EventArgs e) {
			string strClipboard = Clipboard.GetDataObject().GetData(DataFormats.Text).ToString();
			try {
				SharpPrivacy.Instance.AddKey(strClipboard);
			} catch (Exception ex) {
				MessageBox.Show("An error occured: " + ex.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1);
			}
			SharpPrivacy.ReloadKeyRing();
			this.LoadKeys();
			tlvKeys.Refresh();
		}
		
		void mnuKeyMenuDelete_Click(Object sender, System.EventArgs e) {
			if (this.tlvKeys.SelectedNodes.Count == 1) {
				XmlElement xmlKey = (XmlElement)this.tlvKeys.SelectedNodes[0].Tag;
				if (xmlKey.Name == "PublicKey") {
					string strKeyID = xmlKey.GetAttribute("keyid");
					DialogResult drSure = MessageBox.Show("Are you sure you want to delete the key with the id " + strKeyID, "Warning...", MessageBoxButtons.YesNo, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
					if (drSure == DialogResult.Yes) {
						ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
						SharpPrivacy.Instance.RemovePublicKey(lKeyID);
						this.tlvKeys.Nodes.Remove(this.tlvKeys.SelectedNodes[0]);
						this.stbStatus.Text = "Keys deleted";
					}
				} else if (xmlKey.Name == "SecretKey") {
					string strKeyID = xmlKey.GetAttribute("keyid");
					DialogResult drSure = MessageBox.Show("Are you sure you want to delete the key with the id " + strKeyID, "Warning...", MessageBoxButtons.YesNo, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
					if (drSure == DialogResult.Yes) {
						ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
						SharpPrivacy.Instance.RemoveSecretKey(lKeyID);
						this.tlvKeys.Nodes.Remove(this.tlvKeys.SelectedNodes[0]);
						this.stbStatus.Text = "Keys deleted";
					}
				}
			}
			SharpPrivacy.ReloadKeyRing();
			tlvKeys.Refresh();
		}
		
		void mnuKeyMenuAddSignature_Click(Object sender, System.EventArgs e) {
			if (this.tlvKeys.SelectedNodes.Count == 1) {
				XmlElement xmlKey = (XmlElement)this.tlvKeys.SelectedNodes[0].Tag;
				if (xmlKey.Name == "PublicKey") {
					SignKey skSign = new SignKey(xmlKey);
					skSign.ShowDialog();
					if (!skSign.IsCanceled) {
						SharpPrivacy.ReloadKeyRing();
						this.LoadKeys();
						this.stbStatus.Text = "Key signed";
					}
				} else if (xmlKey.Name == "SecretKey") {
					MessageBox.Show("You cannot sign a secret key.", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
				}
			}
		}
		
		void mnuKeyMenuAddID_Click(Object sender, System.EventArgs e) {
			if (this.tlvKeys.SelectedNodes.Count == 1) {
				XmlElement xmlKey = (XmlElement)this.tlvKeys.SelectedNodes[0].Tag;
				if (xmlKey.Name == "PublicKey") {
					ulong lKeyID = UInt64.Parse(xmlKey.GetAttribute("keyid").Substring(2), System.Globalization.NumberStyles.HexNumber);
					XmlElement xmlSecretKey = null;
					try {
						string strSecretKey = SharpPrivacy.Instance.GetSecretKeyProperties(lKeyID);
						XmlDocument xmlDoc = new XmlDocument();
						xmlDoc.LoadXml(strSecretKey);
						xmlSecretKey = xmlDoc.DocumentElement;
					} catch (Exception) {
						MessageBox.Show("You cannot add a UserID to this key as you do not own the fitting secret key!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
						return;
					}
					
					AddUserID auiUserID = new AddUserID(xmlKey, xmlSecretKey);
					auiUserID.ShowDialog();
					if (!auiUserID.IsCanceled) {
						SharpPrivacy.ReloadKeyRing();
						this.LoadKeys();
						this.stbStatus.Text = "UserID added";
					}
				} else if (xmlKey.Name == "SecretKey") {
					MessageBox.Show("You cannot add a user id to a secret key.", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1);
				}
			}
			tlvKeys.Refresh();
		}
		
		void mnuEditCopy_Click(Object sender, System.EventArgs e) {
			this.mnuKeyMenuCopy_Click(sender, e);
		}
		
		void mnuEditPaste_Click(Object sender, System.EventArgs e) {
			this.mnuKeyMenuPaste_Click(sender, e);
		}
		
		void mnuEditDelete_Click(Object sender, System.EventArgs e) {
			this.mnuKeyMenuDelete_Click(sender, e);
		}
		
		void mnuEditSelectAll_Click(Object sender, System.EventArgs e) {
			IEnumerator ieTreeListKeys = this.tlvKeys.Nodes.GetEnumerator();
			while (ieTreeListKeys.MoveNext()) {
				TreeListNode tlnNode = (TreeListNode)ieTreeListKeys.Current;
				tlnNode.Selected = true;
			}
			this.tlvKeys.Refresh();
			this.stbStatus.Text = "All keys selected";
		}
		
		void mnuKeysRefresh_Click(Object sender, System.EventArgs e) {
			this.LoadKeys();
			this.stbStatus.Text = "Keys refreshed";
		}

		void mnuKeyMenuProperties_Click(Object sender, System.EventArgs e) {
			if (this.tlvKeys.SelectedNodes.Count == 1) {
				XmlElement xmlKey = (XmlElement)this.tlvKeys.SelectedNodes[0].Tag;
				if (xmlKey.Name == "SecretKey") {
					string strKeyID = xmlKey.GetAttribute("keyid");
					ulong lKeyID = UInt64.Parse(strKeyID.Substring(2), System.Globalization.NumberStyles.HexNumber);
					string strSecretKey = SharpPrivacy.Instance.GetPublicKeyProperties(lKeyID);
					XmlDocument xmlDoc = new XmlDocument();
					xmlDoc.LoadXml(strSecretKey);
					xmlKey = xmlDoc.DocumentElement;
				}
				
				KeyProperties tpProperties = new KeyProperties(xmlKey);
				tpProperties.ShowDialog();
			}
		}
		
		void tlbToolbar_Click(Object sender, ToolBarButtonClickEventArgs e) {
			switch (tlbToolbar.Buttons.IndexOf(e.Button)) {
				// Generate new keypair
				case 0:
					this.mnuKeysNewKey_Click(sender, new EventArgs());
					break;
				
				// Copy
				case 1:
					this.mnuKeyMenuCopy_Click(sender, new EventArgs());
					break;
				
				// Paste
				case 2:
					this.mnuKeyMenuPaste_Click(sender, new EventArgs());
					break;
				
				// Delete
				case 3:
					this.mnuKeyMenuDelete_Click(sender, new EventArgs());
					break;
			}
		}
		
/*		
		void tlvKeys_MouseUp(Object sender, System.Windows.Forms.MouseEventArgs e) {
			try {
				cmKeyMenu.DestroyHandle();
				cmKeyMenu.Dismiss();
				if ((e.Button == MouseButtons.Right) && (tlvKeys.SelectedNodes.Count == 1)) {
					this.cmKeyMenu.TrackPopup(Cursor.Position);
				}
			} catch (Exception) {}
		}
*/		
		
	}
}

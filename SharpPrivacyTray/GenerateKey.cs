using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;

namespace SharpPrivacy.SharpPrivacyTray {
	/// <summary>
	/// Summary description for GenerateKey2.
	/// </summary>
	public class GenerateKey : System.Windows.Forms.Form {
		// Wizard Items
		private System.Windows.Forms.Panel panel1;
		private System.Windows.Forms.GroupBox groupBox1;
		private System.Windows.Forms.Label lblCaption;
		private System.Windows.Forms.GroupBox groupBox2;
		private System.Windows.Forms.Label lblText;
		private System.Windows.Forms.Button cmdNext;
		private System.Windows.Forms.Button cmdBack;
		private System.Windows.Forms.Button cmdCancel;
		private System.Windows.Forms.PictureBox pbImage;
		
		// Welcome-Page Content
		private Panel panWelcome;
		private Label lblWelcomeDesc;
		
		// KeyData-Page Content
		private Panel panKeyData;
		private DateTimePicker dtExpiration;
		private RadioButton rbNoExpiration;
		private RadioButton rbExpiration;
		private Label lblKeyDataValidUntil;
		private ComboBox cmbKeySize;
		private Label lblKeyDataSize;
		private ComboBox cmbKeyType;
		private Label lblKeyDataType;
		private TextBox txtEmail;
		private Label lblKeyDataEmail;
		private TextBox txtName;
		private Label lblKeyDataName;
		
		// Passphrase-Page Content
		private Panel panPassphrase;
		private Label lblPassphraseText;
		private TextBox txtConfirmation;
		private Label lblConfirmation;
		private TextBox txtPassphrase;
		private Label lblPassphrase;
		
		// Key Generation Page Content
		private Panel panKeyGeneration;
		private ProgressBar pbCurrentProgress;
		private Label lblProgress;
		private ProgressBar pbTotalProgress;
		private CheckBox chkSelfSignatures;
		private CheckBox chkSignatureKey;
		private CheckBox chkEncryptionKey;
		private Label lblWarning;
		private Timer timProgressBar;
		
		// Done-Page Content
		private Panel panDone;
		private Label lblDone;
		
		// Private Member Variables
		private bool bRising = true;
		private bool bCanceled = false;
		
		private System.Threading.Thread tThread;
		
		private static int iKeySize;
		
		public bool Canceled {
			get {
				return bCanceled;
			}
		}
		
		public GenerateKey() {
			// Initialize Wizard Dialog
			InitializeMyComponent();
		}

		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeMyComponent() {
			
			this.panel1 = new System.Windows.Forms.Panel();
			this.lblText = new System.Windows.Forms.Label();
			this.lblCaption = new System.Windows.Forms.Label();
			this.groupBox1 = new System.Windows.Forms.GroupBox();
			this.groupBox2 = new System.Windows.Forms.GroupBox();
			this.cmdNext = new System.Windows.Forms.Button();
			this.cmdBack = new System.Windows.Forms.Button();
			this.cmdCancel = new System.Windows.Forms.Button();
			this.pbImage = new System.Windows.Forms.PictureBox();
			this.panel1.SuspendLayout();
			this.SuspendLayout();
			// 
			// panel1
			// 
			this.panel1.BackColor = System.Drawing.Color.White;
			this.panel1.Controls.Add(this.pbImage);
			this.panel1.Controls.Add(this.lblText);
			this.panel1.Controls.Add(this.lblCaption);
			this.panel1.Location = new System.Drawing.Point(0, 0);
			this.panel1.Name = "panel1";
			this.panel1.Size = new System.Drawing.Size(568, 88);
			this.panel1.TabIndex = 0;
			// 
			// lblText
			// 
			this.lblText.Location = new System.Drawing.Point(32, 32);
			this.lblText.Name = "lblText";
			this.lblText.Size = new System.Drawing.Size(456, 40);
			this.lblText.TabIndex = 1;
			this.lblText.Text = "bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla b" +
				"la bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla bla b" +
				"la bla bla bla bla bla bla bla bla bla bla bla bla bla ";
			// 
			// lblCaption
			// 
			this.lblCaption.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((System.Byte)(0)));
			this.lblCaption.Location = new System.Drawing.Point(8, 8);
			this.lblCaption.Name = "lblCaption";
			this.lblCaption.Size = new System.Drawing.Size(480, 16);
			this.lblCaption.TabIndex = 0;
			this.lblCaption.Text = "Überschrift";
			// 
			// groupBox1
			// 
			this.groupBox1.BackColor = System.Drawing.Color.White;
			this.groupBox1.Location = new System.Drawing.Point(0, 80);
			this.groupBox1.Name = "groupBox1";
			this.groupBox1.Size = new System.Drawing.Size(568, 8);
			this.groupBox1.TabIndex = 1;
			this.groupBox1.TabStop = false;
			// 
			// groupBox2
			// 
			this.groupBox2.Location = new System.Drawing.Point(0, 344);
			this.groupBox2.Name = "groupBox2";
			this.groupBox2.Size = new System.Drawing.Size(568, 8);
			this.groupBox2.TabIndex = 2;
			this.groupBox2.TabStop = false;
			// 
			// cmdNext
			// 
			this.cmdNext.Click += new System.EventHandler(this.cmdNext_Click);
			this.cmdNext.Location = new System.Drawing.Point(480, 360);
			this.cmdNext.Name = "cmdNext";
			this.cmdNext.Size = new System.Drawing.Size(80, 24);
			this.cmdNext.TabIndex = 3;
			this.cmdNext.Text = "Next >";
			// 
			// cmdBack
			// 
			this.cmdBack.Click += new System.EventHandler(this.cmdBack_Click);
			this.cmdBack.Location = new System.Drawing.Point(392, 360);
			this.cmdBack.Name = "cmdBack";
			this.cmdBack.Size = new System.Drawing.Size(80, 24);
			this.cmdBack.TabIndex = 4;
			this.cmdBack.Text = "< Back";
			// 
			// cmdCancel
			// 
			this.cmdCancel.Location = new System.Drawing.Point(304, 360);
			this.cmdCancel.Name = "cmdCancel";
			this.cmdCancel.Size = new System.Drawing.Size(80, 24);
			this.cmdCancel.TabIndex = 5;
			this.cmdCancel.Text = "Cancel";
			// 
			// pbImage
			// 
			this.pbImage.Location = new System.Drawing.Point(492, 11);
			this.pbImage.Name = "pbImage";
			this.pbImage.Size = new System.Drawing.Size(64, 64);
			this.pbImage.TabIndex = 2;
			this.pbImage.TabStop = false;
			
			// Show first Wizardpage
			InitializeWelcomePanel();
			InitializeDonePanel();
			InitializeGenerationPanel();
			InitializeKeyDataPanel();
			InitializePassphrasePanel();
			
			this.lblText.Text = "This wizard guides you through the progress of creating a new OpenPGP keypair.";
			this.lblCaption.Text = "Welcome to the Key Generation Wizard";
			
			this.panDone.Visible = false;
			this.panKeyData.Visible = false;
			this.panKeyGeneration.Visible = false;
			this.panPassphrase.Visible = false;
			
			// GenerateKey2
			this.AcceptButton = this.cmdNext;
			this.CancelButton = this.cmdCancel;
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
			this.ShowInTaskbar = false;
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.ClientSize = new System.Drawing.Size(568, 389);
			this.Controls.Add(this.cmdCancel);
			this.Controls.Add(this.cmdBack);
			this.Controls.Add(this.cmdNext);
			this.Controls.Add(this.groupBox2);
			this.Controls.Add(this.groupBox1);
			this.Controls.Add(this.panel1);
			this.Controls.Add(this.panDone);
			this.Controls.Add(this.panKeyData);
			this.Controls.Add(this.panKeyGeneration);
			this.Controls.Add(this.panPassphrase);
			this.Controls.Add(this.panWelcome);
			this.Name = "GenerateKey2";
			this.Text = "Key Generation Wizard...";
			this.panel1.ResumeLayout(false);
			this.ResumeLayout(false);
		}
		
		private void InitializeWelcomePanel() {
			// panWelcome
			this.panWelcome = new Panel();
			this.panWelcome.Location = new System.Drawing.Point(0, 88);
			this.panWelcome.Name = "panWelcome";
			this.panWelcome.Size = new System.Drawing.Size(568, 256);
			
			this.lblWelcomeDesc = new Label();
			this.lblWelcomeDesc.Location = new System.Drawing.Point(16, 16);
			this.lblWelcomeDesc.Name = "lblWelcomeDesc";
			this.lblWelcomeDesc.Size = new System.Drawing.Size(432, 204);
			this.lblWelcomeDesc.TabIndex = 0;
			this.lblWelcomeDesc.Text = "This wizard guides you through the progress of creating a new OpenPGP keypair.\n\n" + 
			                           "You can use a pair of keys to sign data and enable your business partners to send you confidental data encrypted to your secret key.\n" + 
			                           "Effectively, you need a pair of keys to use SharpPrivacy to its full extent. Only if you just want to verify signed documents, you will not need a keypair of your own.\n\n" +
			                           "For more information about public key cryptography, please have a look into the helpfile.";
			
			this.panWelcome.Controls.Add(lblWelcomeDesc);
			cmdBack.Enabled = false;
		}
		
		private void InitializeKeyDataPanel() {
			this.panKeyData = new Panel();
			this.panKeyData.Location = new System.Drawing.Point(0, 88);
			this.panKeyData.Name = "panKeyData";
			this.panKeyData.Size = new System.Drawing.Size(568, 256);
			
			// dtExpiration
			this.dtExpiration = new DateTimePicker();
			this.dtExpiration.Location = new System.Drawing.Point(156, 144);
			this.dtExpiration.Name = "dtExpiration";
			this.dtExpiration.Size = new System.Drawing.Size(192, 21);
			this.dtExpiration.TabIndex = 11;
			
			// rbNoExpiration
			this.rbNoExpiration = new RadioButton();
			this.rbNoExpiration.Checked = true;
			this.rbNoExpiration.Location = new System.Drawing.Point(132, 172);
			this.rbNoExpiration.Name = "rbNoExpiration";
			this.rbNoExpiration.Size = new System.Drawing.Size(140, 16);
			this.rbNoExpiration.TabIndex = 10;
			this.rbNoExpiration.TabStop = true;
			this.rbNoExpiration.Text = "Key does not expire";
			
			// rbExpiration
			this.rbExpiration = new RadioButton();
			this.rbExpiration.Location = new System.Drawing.Point(132, 148);
			this.rbExpiration.Name = "rbExpiration";
			this.rbExpiration.Size = new System.Drawing.Size(16, 16);
			this.rbExpiration.TabIndex = 9;
			
			// lblKeyDataValidUntil
			this.lblKeyDataValidUntil = new Label();
			this.lblKeyDataValidUntil.Location = new System.Drawing.Point(16, 148);
			this.lblKeyDataValidUntil.Name = "lblKeyDataValidUntil";
			this.lblKeyDataValidUntil.Size = new System.Drawing.Size(92, 16);
			this.lblKeyDataValidUntil.TabIndex = 8;
			this.lblKeyDataValidUntil.Text = "Key Valid Until";
			
			// cmbKeySize
			this.cmbKeySize = new ComboBox();
			this.cmbKeySize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.cmbKeySize.Items.AddRange(new object[] {
															"768",
															"1024",
															"2048",
															"4096"});
			this.cmbKeySize.Location = new System.Drawing.Point(132, 108);
			this.cmbKeySize.Name = "cmbKeySize";
			this.cmbKeySize.Size = new System.Drawing.Size(216, 21);
			this.cmbKeySize.TabIndex = 7;
			this.cmbKeySize.SelectedIndex = 2;
			
			// lblKeyDataSize
			this.lblKeyDataSize = new Label();
			this.lblKeyDataSize.Location = new System.Drawing.Point(16, 112);
			this.lblKeyDataSize.Name = "lblKeyDataSize";
			this.lblKeyDataSize.Size = new System.Drawing.Size(88, 16);
			this.lblKeyDataSize.TabIndex = 6;
			this.lblKeyDataSize.Text = "Key Size";
			
			// cmbKeyType
			this.cmbKeyType = new ComboBox();
			this.cmbKeyType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.cmbKeyType.Items.AddRange(new object[] {
															"ElGamal/DSA",
															"RSA"});
			this.cmbKeyType.Location = new System.Drawing.Point(132, 80);
			this.cmbKeyType.Name = "cmbKeyType";
			this.cmbKeyType.Size = new System.Drawing.Size(216, 21);
			this.cmbKeyType.TabIndex = 5;
			this.cmbKeyType.SelectedIndex = 0;
			
			// lblKeyDataType
			this.lblKeyDataType = new Label();
			this.lblKeyDataType.Location = new System.Drawing.Point(16, 84);
			this.lblKeyDataType.Name = "lblKeyDataType";
			this.lblKeyDataType.Size = new System.Drawing.Size(100, 16);
			this.lblKeyDataType.TabIndex = 4;
			this.lblKeyDataType.Text = "Key Type";
			
			// txtEmail
			this.txtEmail = new TextBox();
			this.txtEmail.Location = new System.Drawing.Point(132, 44);
			this.txtEmail.MaxLength = 50;
			this.txtEmail.Name = "txtEmail";
			this.txtEmail.Size = new System.Drawing.Size(216, 21);
			this.txtEmail.TabIndex = 3;
			this.txtEmail.Text = "";
			
			// lblKeyDataEmail
			this.lblKeyDataEmail = new Label();
			this.lblKeyDataEmail.Location = new System.Drawing.Point(16, 48);
			this.lblKeyDataEmail.Name = "lblKeyDataEmail";
			this.lblKeyDataEmail.Size = new System.Drawing.Size(108, 16);
			this.lblKeyDataEmail.TabIndex = 2;
			this.lblKeyDataEmail.Text = "Your Email Address";
			
			// txtName
			this.txtName = new TextBox();
			this.txtName.Location = new System.Drawing.Point(132, 16);
			this.txtName.MaxLength = 50;
			this.txtName.Name = "txtName";
			this.txtName.Size = new System.Drawing.Size(216, 21);
			this.txtName.TabIndex = 1;
			this.txtName.Text = "";
			
			// lblKeyDataName
			this.lblKeyDataName = new Label();
			this.lblKeyDataName.Location = new System.Drawing.Point(16, 20);
			this.lblKeyDataName.Name = "lblKeyDataName";
			this.lblKeyDataName.Size = new System.Drawing.Size(76, 16);
			this.lblKeyDataName.TabIndex = 0;
			this.lblKeyDataName.Text = "Your Name";
			
			this.panKeyData.Controls.AddRange(new System.Windows.Forms.Control[] {
				this.dtExpiration,
				this.rbNoExpiration,
				this.rbExpiration,
				this.lblKeyDataValidUntil,
				this.cmbKeySize,
				this.lblKeyDataSize,
				this.cmbKeyType,
				this.lblKeyDataType,
				this.txtEmail,
				this.lblKeyDataEmail,
				this.txtName,
				this.lblKeyDataName});
		}
		
		private void InitializePassphrasePanel() {
			
			this.panPassphrase = new Panel();
			this.panPassphrase.Location = new System.Drawing.Point(0, 88);
			this.panPassphrase.Name = "panPassphrase";
			this.panPassphrase.Size = new System.Drawing.Size(568, 256);
			
			// lblPassphrase
			lblPassphrase = new Label();
			this.lblPassphrase.Location = new System.Drawing.Point(16, 128);
			this.lblPassphrase.Name = "lblPassphrase";
			this.lblPassphrase.Size = new System.Drawing.Size(116, 16);
			this.lblPassphrase.TabIndex = 0;
			this.lblPassphrase.Text = "Passphrase";
			
			// txtPassphrase
			txtPassphrase = new TextBox();
			this.txtPassphrase.Location = new System.Drawing.Point(16, 144);
			this.txtPassphrase.Name = "txtPassphrase";
			this.txtPassphrase.Size = new System.Drawing.Size(436, 21);
			this.txtPassphrase.TabIndex = 1;
			this.txtPassphrase.Text = "";
			this.txtPassphrase.PasswordChar = '*';
			
			// lblConfirmation
			lblConfirmation = new Label();
			this.lblConfirmation.Location = new System.Drawing.Point(16, 180);
			this.lblConfirmation.Name = "lblConfirmation";
			this.lblConfirmation.Size = new System.Drawing.Size(172, 16);
			this.lblConfirmation.TabIndex = 2;
			this.lblConfirmation.Text = "Confirm your passphrase";
			
			// txtConfirmation
			txtConfirmation = new TextBox();
			this.txtConfirmation.Location = new System.Drawing.Point(16, 196);
			this.txtConfirmation.Name = "txtConfirmation";
			this.txtConfirmation.Size = new System.Drawing.Size(436, 21);
			this.txtConfirmation.TabIndex = 3;
			this.txtConfirmation.Text = "";
			this.txtConfirmation.PasswordChar = '*';
			
			// lblPassphraseText
			lblPassphraseText = new Label();
			this.lblPassphraseText.Location = new System.Drawing.Point(16, 8);
			this.lblPassphraseText.Name = "lblPassphraseText";
			this.lblPassphraseText.Size = new System.Drawing.Size(460, 112);
			this.lblPassphraseText.TabIndex = 4;
			this.lblPassphraseText.Text = "To save your passphrase while it is stored on your harddisk, it is encrypted to a secret passphrase, that only you should know.\n\nThe passphrase should be at least 8 characters long and contain special characters like '$&§/=', upper and lower case letters, as well as numbers.\n\nBe sure to remember your passphrase, as you will not be able to use your private key without your passphrase!";
			
			this.panPassphrase.Controls.AddRange(new System.Windows.Forms.Control[] {
				this.lblPassphraseText,
				this.txtConfirmation,
				this.lblConfirmation,
				this.txtPassphrase,
				this.lblPassphrase});
		}
		
		private void InitializeGenerationPanel() {
			this.panKeyGeneration = new Panel();
			this.panKeyGeneration.Location = new System.Drawing.Point(0, 88);
			this.panKeyGeneration.Name = "panGeneration";
			this.panKeyGeneration.Size = new System.Drawing.Size(568, 256);
			
			// timProgressBar
			timProgressBar = new Timer();
			this.timProgressBar.Interval = 200;
			this.timProgressBar.Tick += new EventHandler(this.timProgressBar_Tick);
			
			// chkEncryptionKey
			chkEncryptionKey = new CheckBox();
			this.chkEncryptionKey.AutoCheck = false;
			this.chkEncryptionKey.Location = new System.Drawing.Point(24, 24);
			this.chkEncryptionKey.Name = "chkEncryptionKey";
			this.chkEncryptionKey.Size = new System.Drawing.Size(176, 16);
			this.chkEncryptionKey.TabIndex = 0;
			this.chkEncryptionKey.Text = "Generating Encryption Key...";
			
			// chkSignatureKey
			chkSignatureKey = new CheckBox();
			this.chkSignatureKey.AutoCheck = false;
			this.chkSignatureKey.Location = new System.Drawing.Point(24, 48);
			this.chkSignatureKey.Name = "chkSignatureKey";
			this.chkSignatureKey.Size = new System.Drawing.Size(176, 16);
			this.chkSignatureKey.TabIndex = 1;
			this.chkSignatureKey.Text = "Generating Signature Key...";
			
			// chkSelfSignatures
			chkSelfSignatures = new CheckBox();
			this.chkSelfSignatures.AutoCheck = false;
			this.chkSelfSignatures.Location = new System.Drawing.Point(24, 72);
			this.chkSelfSignatures.Name = "chkSelfSignatures";
			this.chkSelfSignatures.Size = new System.Drawing.Size(176, 20);
			this.chkSelfSignatures.TabIndex = 2;
			this.chkSelfSignatures.Text = "Selfsigning Keys...";
			
			// pbTotalProgress
			pbTotalProgress = new ProgressBar();
			this.pbTotalProgress.Location = new System.Drawing.Point(20, 192);
			this.pbTotalProgress.Name = "pbTotalProgress";
			this.pbTotalProgress.Size = new System.Drawing.Size(476, 24);
			this.pbTotalProgress.TabIndex = 3;
			this.pbTotalProgress.Minimum = 0;
			this.pbTotalProgress.Maximum = 100;
			this.pbTotalProgress.Value = 0;
			
			// lblProgress
			lblProgress = new Label();
			this.lblProgress.Location = new System.Drawing.Point(20, 176);
			this.lblProgress.Name = "lblProgress";
			this.lblProgress.Size = new System.Drawing.Size(104, 15);
			this.lblProgress.TabIndex = 4;
			this.lblProgress.Text = "Total Progress";
			
			// lblWarning
			lblWarning = new Label();
			this.lblWarning.Location = new System.Drawing.Point(20, 136);
			this.lblWarning.Name = "lblWarning";
			this.lblWarning.Size = new System.Drawing.Size(250, 15);
			this.lblWarning.TabIndex = 4;
			this.lblWarning.Text = "WARNING! This may take up to 30 minutes!!!";
			
			// pbCurrentProgress
			pbCurrentProgress = new ProgressBar();
			this.pbCurrentProgress.Location = new System.Drawing.Point(224, 68);
			this.pbCurrentProgress.Name = "pbCurrentProgress";
			this.pbCurrentProgress.Size = new System.Drawing.Size(268, 20);
			this.pbCurrentProgress.Step = 1;
			this.pbCurrentProgress.TabIndex = 5;
			this.pbCurrentProgress.Minimum = 0;
			this.pbCurrentProgress.Maximum = 30;
			
			this.panKeyGeneration.Controls.AddRange(new System.Windows.Forms.Control[] {
				this.pbCurrentProgress,
				this.lblProgress,
				this.pbTotalProgress,
				this.chkSelfSignatures,
				this.chkSignatureKey,
				this.chkEncryptionKey,
				this.lblWarning});
			
		}
		
		private void InitializeDonePanel() {
			this.panDone = new Panel();
			this.panDone.Location = new System.Drawing.Point(0, 88);
			this.panDone.Name = "panDone";
			this.panDone.Size = new System.Drawing.Size(568, 256);
			
			// lblDone
			lblDone = new Label();
			this.lblDone.Location = new System.Drawing.Point(20, 16);
			this.lblDone.Name = "lblDone";
			this.lblDone.Size = new System.Drawing.Size(464, 204);
			this.lblDone.TabIndex = 0;
			this.lblDone.Text = "The creation of your keys has been successfully completed. To add more userids to" +
				" the key open the key in the key manager. Furthermore you can use your key to si" +
				"gn data, as well as decrypt data that has been encrypted to your secret key.";
			
			
			this.panDone.Controls.AddRange(new System.Windows.Forms.Control[] {
				this.lblDone});
			
			
		}
		
		private void timProgressBar_Tick(Object sender, EventArgs e) {
			if (this.bRising)
				this.pbCurrentProgress.Value++;
			else
				this.pbCurrentProgress.Value--;
			
			if (this.pbCurrentProgress.Maximum == this.pbCurrentProgress.Value)
				this.bRising = false;
			else if (this.pbCurrentProgress.Minimum == this.pbCurrentProgress.Value)
				this.bRising = true;
			
			Application.DoEvents();
		}
		
		private void StartKeyGeneration() {
			iKeySize = Convert.ToInt32(cmbKeySize.Text);
			this.pbCurrentProgress.Value = 0;
			this.timProgressBar.Start();
			this.cmdCancel.Enabled = false;
			this.cmdNext.Enabled = false;
			
			iKeySize = Int32.Parse(this.cmbKeySize.Text);
			SharpPrivacy.ReloadKeyRing();
			tThread = new System.Threading.Thread(new System.Threading.ThreadStart(Start));
			tThread.Start();
			while (tThread.IsAlive) {
				System.Threading.Thread.Sleep(100);
				Application.DoEvents();
			}
			SharpPrivacy.ReloadKeyRing();
			
			panKeyGeneration.Visible = false;
			panDone.Visible = true;
			cmdCancel.Visible = false;
			cmdBack.Visible = false;
			cmdNext.Enabled = true;
			cmdNext.Text = "Finish";
			
			this.lblText.Text = "Your keypair has been created and is ready for use.";
			this.lblCaption.Text = "Key Generation is Complete";
			
		
		}
		
		private void Start() {
			long lExpiration = this.dtExpiration.Value.Ticks;
			string strPassphrase = this.txtPassphrase.Text;
			SharpPrivacy.Instance.GenerateKey(txtName.Text, txtEmail.Text, cmbKeyType.Text, iKeySize, lExpiration, strPassphrase);
		}
		
		private void cmdNext_Click(Object sender, System.EventArgs e) {
			if (panPassphrase.Visible) {
				if (this.txtConfirmation.Text != this.txtPassphrase.Text) {
					MessageBox.Show("Your passphrase and confirmation are not the same. Please correct your passphrase.", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1);
					return;
				}
				if (this.txtConfirmation.Text.Length < 8) {
					DialogResult drResult = MessageBox.Show("Your passphrase is shorter than 8 characters. It is STRONGLY recommended to use a passphrase of at least 8 characters. Are you sure you want to continue?", "Short Passphrase...", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1);
					if (drResult == DialogResult.No) {
						return;
					}
				}
				panPassphrase.Visible = false;
				panKeyGeneration.Visible = true;
				this.lblText.Text = "Your keys are being created. This progress may take several minutes on older comp" +
				                    "uters and cannot be canceled.";
				this.lblCaption.Text = "Key Generation";
				
				StartKeyGeneration();
			} else if (panKeyData.Visible) {
				if ((this.txtEmail.Text.Length < 5) || (this.txtName.Text.Length < 3)) {
					MessageBox.Show("Please enter your full name as well as your email address!", "Error...", MessageBoxButtons.OK, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1);
					return;
				}
				if (this.cmbKeyType.SelectedIndex == 1) {
					MessageBox.Show("This first beta version does not support the creation of RSA keys. Please wait for the next releases!", "Not Supported...", MessageBoxButtons.OK, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1);
					cmbKeyType.SelectedIndex = 0;
					return;
				}
				panKeyData.Visible = false;
				panPassphrase.Visible = true;
				cmdBack.Enabled = false;
				
				this.lblText.Text = "Your private key will be encrypted to a passphrase, that only you know. Please en" +
				                    "ter a safe passphrase.";
				this.lblCaption.Text = "Key Generation Wizard";
			} else if (panWelcome.Visible) {
				panWelcome.Visible = false;
				panKeyData.Visible = true;
				cmdBack.Visible = true;
				cmdCancel.Visible = true;
				cmdBack.Enabled = true;
				this.lblText.Text = "Here you can enter your personal information stored in the key, as well as " +
				                    "properties such as key length or type for the keypair itself.";
				this.lblCaption.Text = "Personal Data";
			} else if (panDone.Visible) {
				this.Hide();
			}
			
		}
		
		private void cmdBack_Click(object sender, System.EventArgs e) {
			if (panKeyData.Visible) {
				panWelcome.Visible = true;
				panKeyData.Visible = false;
				cmdBack.Enabled = false;
				this.lblText.Text = "This wizard guides you through the progress of creating a new OpenPGP keypair.";
				this.lblCaption.Text = "Welcome to the Key Generation Wizard";
			
				//cmdCancel.Visible = false;
			} else if (panPassphrase.Visible) {
				this.lblText.Text = "Here you can enter your personal information stored in the key, as well as " +
				                    "properties such as key length or type for the keypair itself.";
				this.lblCaption.Text = "Personal Data";
				panPassphrase.Visible = false;
				panKeyData.Visible = true;
			} 
			
		}
		
		private void cmdCancel_Click(object sender, System.EventArgs e) {
			try {
				tThread.Abort();
			} catch (Exception) {}
			this.timProgressBar.Stop();
			this.bCanceled = true;
		}
		
	}
}

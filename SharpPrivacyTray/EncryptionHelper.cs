//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// EncryptionHelper.cs: 
// 	This class implements helper functions for encrypting, decrypting,
//	signing, verifying, etc.
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
using System.Windows.Forms;
using System.Collections;
using System.IO;
using SharpPrivacy.SharpPrivacyLib;
using SharpPrivacy.SharpPrivacyTray;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;

namespace SharpPrivacy {
	
	
	/// <summary>
	/// This class implements helper functions for encrypting, decrypting,
	/// signing, verifying, etc.
	/// </summary>
	/// <remarks>
	/// Note that EncryptionHelper also shows GUI elements!
	/// </remarks>
	public class EncryptionHelper : object {
		
		public static void EncryptFiles(String[] strFiles, PublicKeyRing pkrPublicKeyRing, SecretKeyRing skrSecretKeyRing, bool bEncrypt, bool bSign) {
			
			PublicKeySelector pksSelectKeys = new PublicKeySelector(pkrPublicKeyRing);
			if (bEncrypt) {
				pksSelectKeys.ShowDialog();
				if (pksSelectKeys.SelectedKeys.Count == 0) {
					MessageBox.Show("You did not select a public key to encrypt to. Doing nothing...", "Nothing Done...");
					return;
				}
			}
			
			TransportableSecretKey tskKey = new TransportableSecretKey();
			string strPassphrase = "";
			
			if (bSign) {
				QueryPassphrase qpPassphrase = new QueryPassphrase();
				qpPassphrase.ShowMyDialog(skrSecretKeyRing);
				tskKey = qpPassphrase.SelectedKey;
				strPassphrase = qpPassphrase.Passphrase;
			}
			
			Working wWorking = new Working();
			wWorking.Show();
			
			
			for (int i=0; i<strFiles.Length; i++) {
				byte[] bFileContent = new byte[0];
				try {
					System.IO.FileStream fsFile = new FileStream(strFiles[i], FileMode.Open);
					BinaryReader brReader = new BinaryReader(fsFile);
					bFileContent = brReader.ReadBytes((int)fsFile.Length);
					brReader.Close();
					fsFile.Close();
				} catch (Exception e) {
					wWorking.Hide();
					MessageBox.Show("An error occured while opening the file " + strFiles[i] + ": " + e.Message, "Error...");
					return;
				}
				
				LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
				lmMessage.Binary = bFileContent;
				lmMessage.TimeCreated = DateTime.Now;
				int iLastBackslash = strFiles[i].LastIndexOf("\\");
				lmMessage.Filename = strFiles[i].Substring(iLastBackslash + 1, strFiles[i].Length - iLastBackslash - 1);
				
				SharpPrivacy.OpenPGP.Messages.Message mEncryptionMessage = lmMessage;
				
				if (bSign) {
					SignedMessage smMessage = new SignedMessage();
					smMessage.MessageSigned = lmMessage;
					SignaturePacket spPacket = new SignaturePacket();
					spPacket.Version = SignaturePacketVersionNumbers.v3;
					SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
					spPacket.KeyID = skpKey.PublicKey.KeyID;
					spPacket.HashAlgorithm = HashAlgorithms.SHA1;
					spPacket.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
					spPacket.TimeCreated = DateTime.Now;
					spPacket.SignatureType = SignatureTypes.TextSignature;
					spPacket.Sign(lmMessage.Binary, skpKey, strPassphrase);
					smMessage.Signature = spPacket;
					mEncryptionMessage = smMessage;
				}
				
				CompressedMessage cmMessage = new CompressedMessage();
				cmMessage.Compress(mEncryptionMessage);
				
				wWorking.Progress(20/strFiles.Length);
				
				SymAlgorithms saAlgo = GetSymAlgorithmPreferences(pksSelectKeys.SelectedKeys);
				
				wWorking.Progress(10/strFiles.Length);
				byte[] bReturn = new byte[0];
				if (bEncrypt) {
					SymmetricallyEncryptedDataPacket sedpEncrypted = new SymmetricallyEncryptedDataPacket();
					SymmetricAlgorithm saEncrypt = CipherHelper.CreateSymAlgorithm(saAlgo);
					saEncrypt.Mode = CipherMode.OpenPGP_CFB;
					saEncrypt.GenerateKey();
					byte[] bKey = saEncrypt.Key;
					
					ESKSequence esksKeys = new ESKSequence();
					try {
						 esksKeys = CreateESKSequence(pksSelectKeys.SelectedKeys, AsymActions.Encrypt, saAlgo, bKey);
					} catch (Exception e) {
						wWorking.Hide();
						MessageBox.Show("The following error occured: " + e.Message, "Error...");
						return;
					}
				
					wWorking.Progress(50/strFiles.Length);
				
					ICryptoTransform ictEncryptor = saEncrypt.CreateEncryptor();
					byte[] bMessage = cmMessage.GetEncoded();
					byte[] bOutput = new byte[bMessage.Length];
					ictEncryptor.TransformBlock(bMessage, 0, bMessage.Length, ref bOutput, 0);
					bKey.Initialize();
				
					wWorking.Progress(10/strFiles.Length);
					
					int iOutLength = (saEncrypt.BlockSize >> 3) + 2 + bMessage.Length;
					sedpEncrypted.Body = new byte[iOutLength];
					Array.Copy(bOutput, 0, sedpEncrypted.Body, 0, iOutLength);

					byte[] bESK = esksKeys.GetEncoded();
					byte[] bEncrypted = sedpEncrypted.Generate();
				
					bReturn = new byte[bESK.Length + bEncrypted.Length];
					bESK.CopyTo(bReturn, 0);
					bEncrypted.CopyTo(bReturn, bESK.Length);
				} else {
					wWorking.Progress(60/strFiles.Length);
					bReturn = cmMessage.GetEncoded();
				}
				
				wWorking.Progress(10/strFiles.Length);
				
				try {
					FileStream fsOut = new FileStream(strFiles[i] + ".asc", FileMode.CreateNew);
					BinaryWriter bwWrite = new BinaryWriter(fsOut);
					
					bwWrite.Write(bReturn);
					bwWrite.Close();
					fsOut.Close();
				} catch (IOException io) {
					MessageBox.Show("Could not write to file. The following error occured: " + io.Message, "Error...");
				}
			}
			
			wWorking.Hide();
		}
		
		public static SymAlgorithms GetSymAlgorithmPreferences(ArrayList alPublicKeys) {
			bool bCAST5 = true;
			bool bAES256 = true;
			bool bAES192 = true;
			bool bAES128 = true;
			
			IEnumerator ieKeys = alPublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportablePublicKey))
					continue;
				
				TransportablePublicKey tpkKey = (TransportablePublicKey)ieKeys.Current;
				ulong lKeyID = tpkKey.PrimaryKey.KeyID;
				IEnumerator ieCerts = tpkKey.Certifications.GetEnumerator();
				while (ieCerts.MoveNext()) {
					if (!(ieCerts.Current is CertifiedUserID))
						continue;
					
					CertifiedUserID cuiID = (CertifiedUserID)ieCerts.Current;
					IEnumerator ieSigs = cuiID.Certificates.GetEnumerator();
					while (ieSigs.MoveNext()) {
						if (!(ieSigs.Current is SignaturePacket))
							continue;
						
						SignaturePacket spSig = (SignaturePacket)ieSigs.Current;
						if ((spSig.Version == SignaturePacketVersionNumbers.v4) && (spSig.KeyID == lKeyID)) {
							try {
								bool bTmpCAST5 = false;
								bool bTmpAES256 = false;
								bool bTmpAES192 = false;
								bool bTmpAES128 = false;
								SymAlgorithms[] saThisKey = spSig.FindPreferedSymAlgorithms();
								for (int i=0; i<saThisKey.Length; i++) {
									if (saThisKey[i] == SymAlgorithms.AES128)
										bTmpAES128 = true;
									else if (saThisKey[i] == SymAlgorithms.AES192)
										bTmpAES192 = true;
									else if (saThisKey[i] == SymAlgorithms.AES256)
										bTmpAES256 = true;
									else if (saThisKey[i] == SymAlgorithms.CAST5)
										bTmpCAST5 = true;
								}
								
								if (!bTmpCAST5)
									bCAST5 = false;
								
								if (!bTmpAES256)
									bAES256 = false;
								
								if (!bTmpAES192)
									bAES192 = false;
								
								if (!bTmpAES128)
									bAES128 = false;
							} catch (InvalidOperationException) {}
							
						}
					}
				}
			}
			
			if (bAES256)
				return SymAlgorithms.AES256;
			
			if (bAES192)
				return SymAlgorithms.AES192;
			
			if (bAES128)
				return SymAlgorithms.AES128;
			
			if (bCAST5)
				return SymAlgorithms.CAST5;
			
			return SymAlgorithms.Triple_DES;
		}
		
		public static string EncryptText(string strMessage, PublicKeyRing pkrPublicKeyRing, SecretKeyRing skrSecretKeyRing, bool bSign) {
			PublicKeySelector pksSelectKeys = new PublicKeySelector(pkrPublicKeyRing);
			pksSelectKeys.ShowDialog();
			TransportableSecretKey tskKey = new TransportableSecretKey();
			string strPassphrase = "";
			
			if (bSign) {
				QueryPassphrase qpPassphrase = new QueryPassphrase();
				qpPassphrase.ShowMyDialog(skrSecretKeyRing);
				tskKey = qpPassphrase.SelectedKey;
				strPassphrase = qpPassphrase.Passphrase;
			}
			
			if (pksSelectKeys.SelectedKeys.Count == 0)
				return strMessage;
			
			Working wWorking = new Working();
			wWorking.Show();
			
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
			lmMessage.Text = strMessage;
			lmMessage.TimeCreated = DateTime.Now;
			lmMessage.Filename = "";
			
			SharpPrivacy.OpenPGP.Messages.Message mEncryptionMessage = lmMessage;
			
			if (bSign) {
				SignedMessage smMessage = new SignedMessage();
				smMessage.MessageSigned = lmMessage;
				SignaturePacket spPacket = new SignaturePacket();
				spPacket.Version = SignaturePacketVersionNumbers.v3;
				SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
				spPacket.KeyID = skpKey.PublicKey.KeyID;
				spPacket.HashAlgorithm = HashAlgorithms.SHA1;
				spPacket.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
				spPacket.TimeCreated = DateTime.Now;
				spPacket.SignatureType = SignatureTypes.TextSignature;
				spPacket.Sign(lmMessage.Binary, skpKey, strPassphrase);
				smMessage.Signature = spPacket;
				mEncryptionMessage = smMessage;
			}
			
			CompressedMessage cmMessage = new CompressedMessage();
			cmMessage.Compress(mEncryptionMessage);
			
			wWorking.Progress(20);
			
			SymAlgorithms saAlgo = GetSymAlgorithmPreferences(pksSelectKeys.SelectedKeys);
			
			SymmetricallyEncryptedDataPacket sedpEncrypted = new SymmetricallyEncryptedDataPacket();
			SymmetricAlgorithm saEncrypt = CipherHelper.CreateSymAlgorithm(saAlgo);
			saEncrypt.Mode = CipherMode.OpenPGP_CFB;
			saEncrypt.GenerateKey();
			byte[] bKey = saEncrypt.Key;
			
			wWorking.Progress(10);
			ESKSequence esksKeys = new ESKSequence();
			try {
				 esksKeys = CreateESKSequence(pksSelectKeys.SelectedKeys, AsymActions.Encrypt, saAlgo, bKey);
			} catch (Exception e) {
				wWorking.Hide();
				MessageBox.Show("The following error occured: " + e.Message, "Error...");
				return strMessage;
			}
			
			wWorking.Progress(50);
			
			ICryptoTransform ictEncryptor = saEncrypt.CreateEncryptor();
			byte[] bMessage = cmMessage.GetEncoded();
			byte[] bOutput = new byte[bMessage.Length];
			ictEncryptor.TransformBlock(bMessage, 0, bMessage.Length, ref bOutput, 0);
			bKey.Initialize();
			
			wWorking.Progress(10);
			
			int iOutLength = (saEncrypt.BlockSize >> 3) + 2 + bMessage.Length;
			sedpEncrypted.Body = new byte[iOutLength];
			Array.Copy(bOutput, 0, sedpEncrypted.Body, 0, iOutLength);
			
			byte[] bESK = esksKeys.GetEncoded();
			byte[] bEncrypted = sedpEncrypted.Generate();
			
			byte[] bReturn = new byte[bESK.Length + bEncrypted.Length];
			bESK.CopyTo(bReturn, 0);
			bEncrypted.CopyTo(bReturn, bESK.Length);
			
			wWorking.Progress(10);
			string strReturn = Radix64.Encode(bReturn, true);
			
			strReturn = Armor.WrapMessage(strReturn);
			
			wWorking.Hide();
			return strReturn;
		}
		
		private static ESKSequence CreateESKSequence(ArrayList alKeys, AsymActions aaAction, SymAlgorithms saAlgo, byte[] bSymKey) {
			IEnumerator ieKeys = alKeys.GetEnumerator();
			ESKSequence esksReturn = new ESKSequence();
			
			while (ieKeys.MoveNext()) {
				TransportablePublicKey tpkKey = (TransportablePublicKey)ieKeys.Current;
				PublicKeyPacket pkpKey = tpkKey.FindKey(aaAction);
				
				if (pkpKey == null)
					throw new Exception("Could not find subkey fitting to the selected action. Concerned Key: " + tpkKey.PrimaryUserID);
				
				AsymSessionKeyPacket skpKey = new AsymSessionKeyPacket();
				skpKey.KeyID = pkpKey.KeyID;
				skpKey.PublicAlgorithm = pkpKey.Algorithm;
				skpKey.SymmetricAlgorithm = saAlgo;
				skpKey.SessionKey = bSymKey;
				
				skpKey.EncryptSessionKey(pkpKey);
				
				esksReturn.AddAsymSessionKey(skpKey);
			}
			
			return esksReturn;
		}
		
		public static void DecryptAndVerifyFile(SecretKeyRing skrSecretKeyRing, PublicKeyRing pkrPublicKeyRing, string strFile) {
			System.IO.FileStream fsIn = new FileStream(strFile, FileMode.Open);
			System.IO.BinaryReader brIn = new BinaryReader(fsIn);
			
			byte[] bData = new byte[fsIn.Length];
			brIn.Read(bData, 0, bData.Length);
			
			DecryptAndVerify(skrSecretKeyRing, pkrPublicKeyRing, bData);
		}
		
		public static void DecryptAndVerifyText(SecretKeyRing skrSecretKeyRing, PublicKeyRing pkrPublicKeyRing, string strMessage) {
			byte[] bData = new byte[strMessage.Length];
			bData = System.Text.Encoding.UTF8.GetBytes(strMessage);
			
			DecryptAndVerify(skrSecretKeyRing, pkrPublicKeyRing, bData);
		}
		
		private static void DecryptAndVerify(SecretKeyRing skrSecretKeyRing, PublicKeyRing pkrPublicKeyRing, byte[] bData) {
			string strMessage = System.Text.Encoding.UTF8.GetString(bData);
			ArmorTypes atType = new ArmorTypes();
			string strRest = "";
			string strRadix64 = Armor.RemoveArmor(strMessage, ref atType, ref strRest);
			if (strRadix64.Length > 0)
				bData = Radix64.Decode(strRadix64);
			
			SharpPrivacy.OpenPGP.Messages.Message mContent = null;
			
			if (atType == ArmorTypes.OpenPGPSignature) {
				string strSignature = "";
				string strSignedMessage = Armor.RemoveClearSignatureArmor(strMessage, ref atType, ref strSignature);
				
				strSignedMessage = Radix64.DashUnescape(strSignedMessage);
				strSignedMessage = Radix64.TrimMessage(strSignedMessage);
				SignedMessage smMessage = new SignedMessage();
				Packet[] pPackets = Packet.ParsePackets(strSignature);
				if (!(pPackets[0] is SignaturePacket)) {
					MessageBox.Show("Not a valid cleartext signature!");
					return;
				}
				smMessage.Signature = (SignaturePacket)pPackets[0];
				
				LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
				lmMessage.Text = strSignedMessage;
				smMessage.MessageSigned = lmMessage;
				
				mContent = smMessage;
			} else {
				
				// let us see what kind of message this is
				EncryptedMessage emMessage = new EncryptedMessage();
				try {
					Packet[] pPackets = Packet.ParsePackets(bData);
					emMessage.ParseMessage(pPackets);
					
					if (emMessage.SymmetricallyEncrypted) {
						// Query passphrase for symmetrically encrypted message
						QueryPassphrase qpPassphrase = new QueryPassphrase();
						qpPassphrase.ShowMyDialog();
						string strPassphrase = qpPassphrase.Passphrase;
						
						mContent = emMessage.Decrypt(strPassphrase);
						
					} else {
						ulong lKeyID = emMessage.GetFittingKeyID(skrSecretKeyRing);
						QueryPassphrase qpPassphrase = new QueryPassphrase();
						qpPassphrase.ShowMyDialog(skrSecretKeyRing.Find(lKeyID));
						string strPassphrase = qpPassphrase.Passphrase;
						
						mContent = emMessage.Decrypt(skrSecretKeyRing, strPassphrase);
					}
					
					while ((!(mContent is LiteralMessage)) && (!(mContent is SignedMessage))) {
						if (mContent is CompressedMessage) {
							mContent = ((CompressedMessage)mContent).Uncompress();
						} else {
							MessageBox.Show("This is not a valid OpenPGP message!");
							return;
						}
					}
				} catch (Exception ee) {
					MessageBox.Show("There was an error decrypting your message: " + ee.Message);
					return;
				}
			}
			
			LiteralMessage lmContent = new LiteralMessage();
			string strDisplay = "";
			if (mContent is SignedMessage) {
				SignedMessage smContent = (SignedMessage)mContent;
				lmContent = smContent.MessageSigned;
				strDisplay += "*** OpenPGP Signed Message ***\r\n";
				strDisplay += "*** Signature Status: " + smContent.Verify(pkrPublicKeyRing) + " ***\r\n";
				strDisplay += "*** Signing Key: " + smContent.Signature.KeyID.ToString("x") + " ***\r\n";
				strDisplay += "*** Signing Date: " + smContent.Signature.TimeCreated.ToString() + "***\r\n\r\n";
			} else if (mContent is LiteralMessage) {
				lmContent = (LiteralMessage)mContent;
				strDisplay += "*** OpenPGP Encrypted Message ***\r\n\r\n";
			} else {
				MessageBox.Show("An error occured: Could not find an encrypted or signed message!", "Error...");
				return;
			}
			
			if (lmContent.DataFormat == DataFormatTypes.Text) {
				strDisplay += lmContent.Text;
				strDisplay += "\r\n\r\n*** End OpenPGP Message ***\r\n";
				PlaintextViewer pvViewer = new PlaintextViewer();
				pvViewer.MessageText = strDisplay;
				pvViewer.Show();
			} else {
				if (MessageBox.Show(strDisplay, "Signature Status...", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1) == DialogResult.OK) {
					System.Windows.Forms.SaveFileDialog sfdSave = new SaveFileDialog();
					sfdSave.OverwritePrompt = true;
					sfdSave.Filter = "All Files (*.*)|*.*";
					sfdSave.FileName = lmContent.Filename;
					sfdSave.ShowDialog();
					if (sfdSave.FileName.Length > 0) {
						System.IO.FileStream fsOut = new FileStream(sfdSave.FileName, FileMode.CreateNew);
						System.IO.BinaryWriter bwOut = new BinaryWriter(fsOut);
						bwOut.Write(lmContent.Binary);
						bwOut.Close();
						fsOut.Close();
					}
				}
			}
		}
		
		
		public static string ClearTextSign(string strMessage, SecretKeyRing skrKeyRing) {
			SignaturePacket spSign = new SignaturePacket();
			
			strMessage = Radix64.TrimMessage(strMessage);
			QueryPassphrase qpPassphrase = new QueryPassphrase();
			qpPassphrase.ShowMyDialog(skrKeyRing);
			string strPassphrase = qpPassphrase.Passphrase;
			TransportableSecretKey tskKey = qpPassphrase.SelectedKey;
			SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
			
			Working wWorking = new Working();
			wWorking.Show();
			
			spSign.HashAlgorithm = HashAlgorithms.SHA1;
			spSign.Format = PacketFormats.New;
			
			wWorking.Progress(10);
			
			SignatureSubPacket sspCreator = new SignatureSubPacket();
			sspCreator.Type = SignatureSubPacketTypes.IssuerKeyID;
			sspCreator.KeyID = skpKey.PublicKey.KeyID;
			SignatureSubPacket sspCreationTime = new SignatureSubPacket();
			sspCreationTime.Type = SignatureSubPacketTypes.SignatureCreationTime;
			sspCreationTime.TimeCreated = DateTime.Now;
			spSign.HashedSubPackets = new SignatureSubPacket[2];
			spSign.HashedSubPackets[0] = sspCreator;
			spSign.HashedSubPackets[1] = sspCreationTime;
			
			wWorking.Progress(20);

			//spSign.KeyID = skpKey.PublicKey.KeyID;
			//spSign.TimeCreated = DateTime.Now;
			spSign.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
			spSign.SignatureType = SignatureTypes.TextSignature;
			spSign.Version = SignaturePacketVersionNumbers.v4;
			
			wWorking.Progress(10);
			
			byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(strMessage);
			spSign.Sign(bMessage, skpKey, strPassphrase);
			
			wWorking.Progress(40);
			byte[] bSignature = spSign.Generate();
			
			string strSignature = Radix64.Encode(bSignature, true);
			
			wWorking.Progress(20);
			
			string strFinal = Armor.WrapCleartextSignature(strMessage, strSignature);
			
			wWorking.Hide();
			
			return strFinal;
		}
		
	}
}


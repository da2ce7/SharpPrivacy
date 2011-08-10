//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SharpPrivacyLibrary.cs
// 	Class for easily working with the OpenPGP Protocol
//
// Author(s):
//  Roberto Rossi
//
// Version: 0.2.0
//
// Changelog:
//	- 18.02.2004: Created this file.
//	- 18.02.2004: Added this header for the first beta release.
//  - 28.02.2004: Documentation draft
//
// (C) 2004, Roberto Rossi

using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using System.Collections;
using System.Reflection;
using System.IO;

namespace SharpPrivacy.SharpPrivacyLib {
	
	/// <summary>
	/// Singleton reusable component realizing a full implementation of the RFC2440.
	/// This is the service provider for every OpenPGP operation.
	/// </summary>
	public class SharpPrivacyLibrary {
		private static string productVersion = "SharpPrivacyLibrary v0.2";
		private SecretKeyRing skrSecretKeyRing = new SecretKeyRing();
		private PublicKeyRing pkrPublicKeyRing = new PublicKeyRing();
		private string publicKeyRingFile = null;
		private string secretKeyRingFile = null;
		private static SharpPrivacyLibrary instance = null;
		private static int ldapPort = 389;
		private static string ldapKeyServer = "keyserver.pgp.com";

		public static string ApplicationVersionInfos {
			get {
				return productVersion;
			}
		}

		/// <summary>
		/// Gets the current instance of the service provider. Creates a new instance if no exists.
		/// </summary>
		public static SharpPrivacyLibrary Instance {
			get	{
				if(instance != null)
					return instance;
				else
					return instance = new SharpPrivacyLibrary();
			}
		}

		/// <summary>
		/// LDAP service port on remote host
		/// </summary>
		public static int LdapPort {
			get {
				return ldapPort;
			}
			set {
				ldapPort = value;
			}
		}
		/// <summary>
		/// LDAP remote server
		/// </summary>
		public static string LdapKeyServer {
			get {
				return ldapKeyServer;
			}
			set {
				if (value != null)
					ldapKeyServer = value;
			}
		}

		/// <summary>
		/// Default constructor
		/// </summary>
		private SharpPrivacyLibrary() {
			instance = this;
			this.LoadRings();
		}

		/// <summary>
		/// Get/Set the location of a public keyring file loading its content
		/// </summary>
		public string PublicKeyRingFile {
			get {
				return this.publicKeyRingFile;
			}
			set {
				this.publicKeyRingFile = value;
				string errorXML = this.LoadPublicRing();
				if(errorXML != "<ERROR code=\"0\">")
					throw new Exception(errorXML);
			}
		}

		/// <summary>
		/// Get/Set the location of a secret keyring file loading its content
		/// </summary>
		public string SecretKeyRingFile {
			get {
				return this.secretKeyRingFile;
			}
			set {
				this.secretKeyRingFile = value;
				string errorXML = this.LoadSecretRing();
				if(errorXML != "<ERROR code=\"0\">")
					throw new Exception(errorXML);
			}
		}

		/// <summary>
		/// Gets the current public ring
		/// </summary>
		public PublicKeyRing PublicRing {
			get {
				return this.pkrPublicKeyRing;
			}
		}
		/// <summary>
		/// Gets the current secret ring
		/// </summary>
		public SecretKeyRing SecretRing {
			get {
				return this.skrSecretKeyRing;
			}
		}
		/// <summary>
		/// Loads public and secret ring
		/// </summary>
		/// <returns>xml result</returns>
		public string LoadRings() {
			string errorXML = "<ERROR code=\"0\">";
			string strPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
			this.SecretKeyRingFile = strPath + "/SharpPrivacy/sec_keyring.asc";
			this.PublicKeyRingFile = strPath + "/SharpPrivacy/pub_keyring.asc";
			return errorXML;
		}

		/// <summary>
		/// Loads the secret ring
		/// </summary>
		/// <returns>xml result</returns>
		private string LoadSecretRing() {
			string strPath = null;
			this.skrSecretKeyRing = new SecretKeyRing();
			if (!System.IO.File.Exists(this.SecretKeyRingFile)) {
				System.Console.WriteLine("SharpPrivacy was unable to find a keyring. This might be due to you starting this program for the first time. A new keyring will be created in your home directory.");
				strPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
				try {
					if(!System.IO.Directory.Exists(strPath + "/SharpPrivacy"))
						System.IO.Directory.CreateDirectory(strPath + "/SharpPrivacy");
				} catch (Exception e) {
					this.SecretKeyRingFile = null;
					System.Console.WriteLine("Error creating the SharpPrivacy home directory:");
					System.Console.WriteLine("error " + e.Message);
					return "<ERROR code=\"3\">";
				} 
				try {
					FileStream fsTmp = System.IO.File.Create(this.SecretKeyRingFile);
					fsTmp.Close();
				} catch (Exception e) {
					this.SecretKeyRingFile = null;
					System.Console.WriteLine("Error creating the secret keyring file:" + e.Message);
					System.Console.WriteLine("error");
					return "<ERROR code=\"4\">";
				}
			}
			skrSecretKeyRing.Load(this.SecretKeyRingFile);
			return "<ERROR code=\"0\">";
		}

		/// <summary>
		/// Load the public ring
		/// </summary>
		/// <returns>xml result</returns>
		private string LoadPublicRing() {
			string strPath = null;
			this.pkrPublicKeyRing = new PublicKeyRing();
			if (!System.IO.File.Exists(this.PublicKeyRingFile)) {
				System.Console.WriteLine("SharpPrivacy was unable to find a keyring. This might be due to you starting this program for the first time. A new keyring will be created in your home directory.");
				strPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
				try {
					if(!System.IO.Directory.Exists(strPath + "/SharpPrivacy"))
						System.IO.Directory.CreateDirectory(strPath + "/SharpPrivacy");
				} catch (Exception e) {
					this.PublicKeyRingFile = null;
					System.Console.WriteLine("Error creating the SharpPrivacy home directory:");
					System.Console.WriteLine("error " + e.Message);
					return "<ERROR code=\"1\">";
				}
				try {
					FileStream fsTmp = System.IO.File.Create(this.PublicKeyRingFile);
					fsTmp.Close();
				} catch (Exception e) {
					this.PublicKeyRingFile = null;
					System.Console.WriteLine("Error creating the public keyring file:");
					System.Console.WriteLine("error " + e.Message);
					return "<ERROR code=\"2\">";
				}
			}
			pkrPublicKeyRing.Load(this.PublicKeyRingFile);
			return "<ERROR code=\"0\">";
		}

		/// <summary>
		/// Decrypts and/or Verifies a signed/crypted text
		/// </summary>
		/// <param name="strMessage">the signed/crypted text</param>
		/// <param name="strPassphrase">the passphrase for the local secret key if needed for decripting purpose</param>
		/// <returns>verifying process result</returns>
		public string DecryptAndVerifyText(string strMessage, string strPassphrase) {
			byte[] bData = new byte[strMessage.Length];
			bData = System.Text.Encoding.UTF8.GetBytes(strMessage);
			return DecryptAndVerify(bData, strPassphrase, null);
		}

		/// <summary>
		/// Decrypts and/or Verifies a signed/crypted file
		/// </summary>
		/// <param name="strFile">the signed/crypted file</param>
		/// <param name="strPassphrase">the passphrase for the local secret key if needed for decripting purpose</param>
		/// <param name="fileOut">the decrypted file location if one produced</param>
		/// <returns>verifying process result</returns>
		public string DecryptAndVerifyFile(string strFile, string strPassphrase, string fileOut) {
			System.IO.FileStream fsIn = new FileStream(strFile, FileMode.Open);
			System.IO.BinaryReader brIn = new BinaryReader(fsIn);
			
			byte[] bData = new byte[fsIn.Length];
			brIn.Read(bData, 0, bData.Length);
			brIn.Close();
			
			return DecryptAndVerify(bData, strPassphrase, fileOut);
		}

		/// <summary>
		/// Verifies the signature given a signed file and a signature file
		/// </summary>
		/// <param name="strFile">signature file path</param>
		/// <param name="fileToVerify">signed file</param>
		/// <returns></returns>
		public string FileSignatureVerify(string strFile, string fileToVerify) {
			System.IO.FileStream fsIn = new FileStream(strFile, FileMode.Open);
			System.IO.BinaryReader brIn = new BinaryReader(fsIn);
			
			byte[] bData = new byte[fsIn.Length];
			brIn.Read(bData, 0, bData.Length);
			brIn.Close();
			
			return this.FileSignatureVerify(bData, fileToVerify);
		}

		/// <summary>
		/// Verifies the signature given a signed file and a signature file
		/// </summary>
		/// <param name="strFile">signature file bytes</param>
		/// <param name="fileToVerify">signed file</param>
		/// <returns></returns>
		private string FileSignatureVerify(byte[] bData, string fileToVerify) {
			SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages.Message mContent = null;
			byte[] decodedbData = null;
			string strMessage = System.Text.Encoding.UTF8.GetString(bData);
			ArmorTypes atType = new ArmorTypes();
			string strRest = "";
			string strRadix64 = Armor.RemoveArmor(strMessage, ref atType, ref strRest);
			if (strRadix64.Length > 0)
				decodedbData = Radix64.Decode(strRadix64);

			if (atType == ArmorTypes.OpenPGPSignature) {
				SignedMessage smMessage = new SignedMessage();
				Packet[] pPackets;

				pPackets = Packet.ParsePackets(decodedbData);

				if (!(pPackets[0] is SignaturePacket)) {
					throw new Exception("Not a valid cleartext signature!");
				}
				
				smMessage.Signature = (SignaturePacket)pPackets[0];

				mContent = smMessage;
			} else {
				// let us see what kind of message this is
				Packet[] pPackets;
				try {
					pPackets = Packet.ParsePackets(bData);
					mContent = new SignedMessage();
					((SignedMessage)mContent).Signature = (SignaturePacket)pPackets[0];
					//((SignedMessage)mContent).OnePassSigned = false;
				} catch (Exception ee) {
					throw new Exception("There was an error decrypting your message: " + ee.Message);
				}
			}

			byte[] bFileContent = new byte[0];
			try {
				System.IO.FileStream fsFile = new FileStream(fileToVerify, FileMode.Open);
				BinaryReader brReader = new BinaryReader(fsFile);
				bFileContent = brReader.ReadBytes((int)fsFile.Length);
				brReader.Close();
				fsFile.Close();
			} catch (Exception e) {
				throw new Exception("An error occured while opening the file " + e.Message);
			}

			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
			lmMessage.Binary = bFileContent;
			lmMessage.TimeCreated = ((SignedMessage)mContent).Signature.TimeCreated;
			lmMessage.Filename = fileToVerify;
			((SignedMessage)mContent).MessageSigned = lmMessage;

			LiteralMessage lmContent = new LiteralMessage();
			string strDisplay = "";
			if (mContent is SignedMessage) {
				SignedMessage smContent = (SignedMessage)mContent;
				lmContent = smContent.MessageSigned;
				strDisplay += "*** OpenPGP Signed Message ***\r\n";
				strDisplay += "*** Signature Status: " + smContent.Verify(pkrPublicKeyRing) + " ***\r\n";
				strDisplay += "*** Signing Key: " + smContent.Signature.KeyID.ToString("x") + " ***\r\n";
				try {
					try {
						strDisplay += "*** Signing Key Expiration: " + pkrPublicKeyRing.Find(smContent.Signature.KeyID,true).KeyExpirationTime + " ***\r\n";
					} catch(Exception e) {
						if(e.Message.Equals("never")) {
							strDisplay += "*** Signing Key Expiration: "+e.Message+" ***\r\n";
						} else {
							throw new Exception("Signing_Key_Not_Available");
						}

					}
					try {
						strDisplay += "*** Signing Key Revoked: "+ this.pkrPublicKeyRing.isRevoked(smContent.Signature.KeyID) +" ***\r\n";
					} catch(Exception e) {
						string msg = e.Message;
						strDisplay += "*** Signing Key Revoked: Revocation_Key_Not_Available ***\r\n";
					}
				} 
				catch (Exception e) {
					string warn = e.Message;
					strDisplay += "*** Signing Key Expiration: " + SignatureStatusTypes.Signing_Key_Not_Available + " ***\r\n";
				}
				strDisplay += "*** Signing Date: " + smContent.Signature.TimeCreated.ToString() + "***\r\n\r\n";
			} else if (mContent is LiteralMessage) {
				lmContent = (LiteralMessage)mContent;
				strDisplay += "*** OpenPGP Encrypted Message ***\r\n\r\n";
			} else {
				throw new Exception("An error occured: Could not find an encrypted or signed message!");
			}
			
			if (lmContent.DataFormat == DataFormatTypes.Text) {
				strDisplay += lmContent.Text;
				strDisplay += "\r\n\r\n*** End OpenPGP Message ***\r\n";
			} 
			return strDisplay;
		}

		/// <summary>
		/// Method handling decrypting and verifying
		/// </summary>
		/// <param name="bData">data to be decrypted</param>
		/// <param name="strPassphrase">passphrase</param>
		/// <param name="fileOut">the decrypted file location if one produced</param>
		/// <returns>verifying process result</returns>
		private string DecryptAndVerify(byte[] bData, string strPassphrase, string fileOut)  {
			string strMessage = System.Text.Encoding.UTF8.GetString(bData);
			ArmorTypes atType = new ArmorTypes();
			string strRest = "";
			string strRadix64 = Armor.RemoveArmor(strMessage, ref atType, ref strRest);
			if (strRadix64.Length > 0)
				bData = Radix64.Decode(strRadix64);
			
			SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages.Message mContent = null; 
			
			if (atType == ArmorTypes.OpenPGPSignedMessage) {
				string strSignature = "";
				string strSignedMessage = Armor.RemoveClearSignatureArmor(strMessage, ref atType, ref strSignature);
				
				strSignedMessage = Radix64.DashUnescape(strSignedMessage);
				strSignedMessage = Radix64.TrimMessage(strSignedMessage);
				SignedMessage smMessage = new SignedMessage();
				Packet[] pPackets;

				pPackets = Packet.ParsePackets(strSignature);

				if (!(pPackets[0] is SignaturePacket)) {
					throw new Exception("Not a valid cleartext signature!");
				}
				smMessage.Signature = (SignaturePacket)pPackets[0];
				
				LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
				lmMessage.Text = strSignedMessage;
				smMessage.MessageSigned = lmMessage;
				
				mContent = smMessage;
			} else {
				
				// let us see what kind of message this is
				EncryptedMessage emMessage = new EncryptedMessage();
				Packet[] pPackets;
				try {
					pPackets = Packet.ParsePackets(bData);
					try {
						emMessage.ParseMessage(pPackets);

						if (emMessage.SymmetricallyEncrypted) {
							// Query passphrase for symmetrically encrypted message
						
							mContent = emMessage.Decrypt(strPassphrase);
						
						} else {
							ulong lKeyID = emMessage.GetFittingKeyID(skrSecretKeyRing);
							mContent = emMessage.Decrypt(skrSecretKeyRing, strPassphrase);
						}
					} catch (Exception) {
						mContent = new CompressedMessage();
						mContent.ParseMessage(pPackets);
					}
					
					while ((!(mContent is LiteralMessage)) && (!(mContent is SignedMessage))) {
						if (mContent is CompressedMessage) {
							mContent = ((CompressedMessage)mContent).Uncompress();
						} else {
							throw new Exception("This is not a valid OpenPGP message!");
						}
					}
				} catch (Exception ee) {
					throw new Exception("There was an error decrypting your message: " + ee.Message);
				}
			}
			
			LiteralMessage lmContent = new LiteralMessage();
			string strDisplay = "";
			if (mContent is SignedMessage) {
				SignedMessage smContent = (SignedMessage)mContent;
				lmContent = smContent.MessageSigned;
				strDisplay += "*** OpenPGP Signed Message ***\r\n";
				strDisplay += "*** Signature Status: " + smContent.Verify(pkrPublicKeyRing) + " ***\r\n";
				strDisplay += "*** Signing Key Dec: " + smContent.Signature.KeyID.ToString() + " ***\r\n";
				strDisplay += "*** Signing Key Hex: " + smContent.Signature.KeyID.ToString("x") + " ***\r\n";
				try {
					try {
						strDisplay += "*** Signing Key Expiration: " + pkrPublicKeyRing.Find(smContent.Signature.KeyID,true).KeyExpirationTime + " ***\r\n";
					} catch(Exception e) {
						if(e.Message.Equals("never"))
							strDisplay += "*** Signing Key Expiration: "+e.Message+" ***\r\n";
						else
							throw new Exception("Signing_Key_Not_Available");

					}
					try {
						strDisplay += "*** Signing Key Revoked: "+ this.pkrPublicKeyRing.isRevoked(smContent.Signature.KeyID) +" ***\r\n";
					} catch(Exception e) {
						string msg = e.Message;
						strDisplay += "*** Signing Key Revoked: Revocation_Key_Not_Available ***\r\n";
					}
				} catch (Exception e) {
					string warn = e.Message;
					strDisplay += "*** Signing Key Expiration: " + SignatureStatusTypes.Signing_Key_Not_Available + " ***\r\n";
				}
				strDisplay += "*** Signing Date: " + smContent.Signature.TimeCreated.ToString() + "***\r\n\r\n";
			} else if (mContent is LiteralMessage) {
				lmContent = (LiteralMessage)mContent;
				strDisplay += "*** OpenPGP Encrypted Message ***\r\n\r\n";
			} else {
				throw new Exception("An error occured: Could not find an encrypted or signed message!");
			}
			
			if (lmContent.DataFormat == DataFormatTypes.Text) {
				strDisplay += lmContent.Text;
				strDisplay += "\r\n\r\n*** End OpenPGP Message ***\r\n";
				if(fileOut != null && fileOut != "") {
					System.IO.FileStream fsOut = new FileStream(fileOut, FileMode.Create);
					System.IO.BinaryWriter bwOut = new BinaryWriter(fsOut);
					bwOut.Write(lmContent.Binary);
					bwOut.Close();
					fsOut.Close();
				}
			} else {
				System.IO.FileStream fsOut = new FileStream(fileOut, FileMode.Create);
				System.IO.BinaryWriter bwOut = new BinaryWriter(fsOut);
				bwOut.Write(lmContent.Binary);
				bwOut.Close();
				fsOut.Close();
			}
			return strDisplay;
		}

		/// <summary>
		/// Methond handling encryption/signing
		/// </summary>
		/// <param name="strFiles">file list to be encrypted</param>
		/// <param name="tskKey">secret key needed for encyption purpose</param>
		/// <param name="tpkKeys">public key needed for signing purpose</param>
		/// <param name="strPassphrase">passphrase for secret key</param>
		/// <param name="bEncrypt">encrypt files?</param>
		/// <param name="bSign">sign files?</param>
		public void EncryptFiles(String[] strFiles, TransportableSecretKey tskKey, ArrayList tpkKeys, string strPassphrase, bool bEncrypt, bool bSign, bool embedMsg) {
			if(this.pkrPublicKeyRing == null || this.skrSecretKeyRing == null) {
				throw new Exception("<ERROR code=\"5\">");
			}

			if (bSign && tskKey == null) {
				throw new Exception("Need a Private Key To Sign!");
			}

			if (bEncrypt && (tpkKeys == null || tpkKeys.Count < 1)) {
				throw new Exception("Need Public Keys To Encrypt!");
			}
			
			for (int i=0; i<strFiles.Length; i++) {
				byte[] bFileContent = new byte[0];
				try {
					System.IO.FileStream fsFile = new FileStream(strFiles[i], FileMode.Open);
					BinaryReader brReader = new BinaryReader(fsFile);
					bFileContent = brReader.ReadBytes((int)fsFile.Length);
					brReader.Close();
					fsFile.Close();
				} catch (Exception e) {
					throw new Exception("An error occured while opening the file " + strFiles[i] + ": " + e.Message);
				}
				
				LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
				lmMessage.Binary = bFileContent;
				lmMessage.TimeCreated = DateTime.Now;
				int iLastBackslash = strFiles[i].LastIndexOf("\\");
				lmMessage.Filename = strFiles[i].Substring(iLastBackslash + 1, strFiles[i].Length - iLastBackslash - 1);
				
				SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages.Message mEncryptionMessage = lmMessage;
				
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
				
				byte[] bReturn = new byte[0];
				if (bEncrypt) {
					SymAlgorithms saAlgo = GetSymAlgorithmPreferences(tpkKeys);
					SymmetricallyEncryptedDataPacket sedpEncrypted = new SymmetricallyEncryptedDataPacket();
					SymmetricAlgorithm saEncrypt = CipherHelper.CreateSymAlgorithm(saAlgo);
					saEncrypt.Mode = CipherMode.OpenPGP_CFB;
					saEncrypt.GenerateKey();
					byte[] bKey = saEncrypt.Key;
					
					ESKSequence esksKeys = new ESKSequence();
					try {
						esksKeys = CreateESKSequence(tpkKeys, AsymActions.Encrypt, saAlgo, bKey);
					} catch (Exception e) {
						throw new Exception("The following error occured: " + e.Message);
					}
				
					ICryptoTransform ictEncryptor = saEncrypt.CreateEncryptor();
					byte[] bMessage = cmMessage.GetEncoded();
					byte[] bOutput = new byte[bMessage.Length];
					ictEncryptor.TransformBlock(bMessage, 0, bMessage.Length, ref bOutput, 0);
					bKey.Initialize();
					
					int iOutLength = (saEncrypt.BlockSize >> 3) + 2 + bMessage.Length;
					sedpEncrypted.Body = new byte[iOutLength];
					Array.Copy(bOutput, 0, sedpEncrypted.Body, 0, iOutLength);

					byte[] bESK = esksKeys.GetEncoded();
					byte[] bEncrypted = sedpEncrypted.Generate();
				
					bReturn = new byte[bESK.Length + bEncrypted.Length];
					bESK.CopyTo(bReturn, 0);
					bEncrypted.CopyTo(bReturn, bESK.Length);
				} else {
					if(embedMsg) {
						bReturn = cmMessage.GetEncoded();
					} else {
						byte[] bSignature = ((SignedMessage)mEncryptionMessage).Signature.Generate();
						string strSignature = Radix64.Encode(bSignature, true);
						string strFinal = Armor.WrapCleartextSignature(strSignature);
						try {
							FileStream fsOut = new FileStream(strFiles[i] + ".asc", FileMode.Create);
							StreamWriter bwWrite = new StreamWriter(fsOut);
						
							bwWrite.Write(strFinal);
							bwWrite.Close();
							fsOut.Close();
							return;
						} catch (IOException io) {
							throw new Exception("Could not write to file. The following error occured: " + io.Message);
						}
					}
				}
				
				try {
					FileStream fsOut = new FileStream(strFiles[i] + ".asc", FileMode.Create);
					BinaryWriter bwWrite = new BinaryWriter(fsOut);
					
					bwWrite.Write(bReturn);
					bwWrite.Close();
					fsOut.Close();
				} catch (IOException io) {
					throw new Exception("Could not write to file. The following error occured: " + io.Message);
				}
			}
		}

		/// <summary>
		/// Method handling encryption/signing
		/// </summary>
		/// <param name="strMessage">text to be encrypted</param>
		/// <param name="tskKey">secret key needed for encyption purpose</param>
		/// <param name="tpkKeys">public key needed for signing purpose</param>
		/// <param name="bSign">sign text?</param>
		/// <param name="strPassphrase">passphrase for the secret key</param>
		/// <returns>the encrypted text</returns>
		public string EncryptText(string strMessage, TransportableSecretKey tskKey, ArrayList tpkKeys,  bool bSign, string strPassphrase) {
			if(this.pkrPublicKeyRing == null || this.skrSecretKeyRing == null) {
				throw new Exception("<ERROR code=\"5\">");
			}

			if(bSign && tskKey == null) {
				throw new Exception("Need a Private Key To Sign!");
			}
			
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
			lmMessage.Text = strMessage;
			lmMessage.TimeCreated = DateTime.Now;
			lmMessage.Filename = "";
			
			SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages.Message mEncryptionMessage = lmMessage;
			
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
			
			SymAlgorithms saAlgo = GetSymAlgorithmPreferences(tpkKeys);
			
			SymmetricallyEncryptedDataPacket sedpEncrypted = new SymmetricallyEncryptedDataPacket();
			SymmetricAlgorithm saEncrypt = CipherHelper.CreateSymAlgorithm(saAlgo);
			saEncrypt.Mode = CipherMode.OpenPGP_CFB;
			saEncrypt.GenerateKey();
			byte[] bKey = saEncrypt.Key;
			
			ESKSequence esksKeys = new ESKSequence();
			try {
				esksKeys = CreateESKSequence(tpkKeys, AsymActions.Encrypt, saAlgo, bKey);
			} catch (Exception e) {
				throw new Exception("The following error occured: " + e.Message);
			}
			
			ICryptoTransform ictEncryptor = saEncrypt.CreateEncryptor();
			byte[] bMessage = cmMessage.GetEncoded();
			byte[] bOutput = new byte[bMessage.Length];
			ictEncryptor.TransformBlock(bMessage, 0, bMessage.Length, ref bOutput, 0);
			bKey.Initialize();
			
			int iOutLength = (saEncrypt.BlockSize >> 3) + 2 + bMessage.Length;
			sedpEncrypted.Body = new byte[iOutLength];
			Array.Copy(bOutput, 0, sedpEncrypted.Body, 0, iOutLength);
			
			byte[] bESK = esksKeys.GetEncoded();
			byte[] bEncrypted = sedpEncrypted.Generate();
			
			byte[] bReturn = new byte[bESK.Length + bEncrypted.Length];
			bESK.CopyTo(bReturn, 0);
			bEncrypted.CopyTo(bReturn, bESK.Length);
			
			string strReturn = Radix64.Encode(bReturn, true);
			
			strReturn = Armor.WrapMessage(strReturn);
			
			return strReturn;
		}

		/// <summary>
		/// Text signing
		/// </summary>
		/// <param name="strMessage">text to be signed</param>
		/// <param name="tskKey">secret key for signing purpose</param>
		/// <param name="strPassphrase">passphrase for the secret key</param>
		/// <returns>the signed text</returns>
		public string ClearTextSign(string strMessage, TransportableSecretKey tskKey, string strPassphrase, bool embedMessage) {
			SignaturePacket spSign = new SignaturePacket();
			
			strMessage = Radix64.TrimMessage(strMessage);
		
			SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
			
			spSign.HashAlgorithm = HashAlgorithms.SHA1;
			spSign.Format = PacketFormats.New;
			
			SignatureSubPacket sspCreator = new SignatureSubPacket();
			sspCreator.Type = SignatureSubPacketTypes.IssuerKeyID;
			sspCreator.KeyID = skpKey.PublicKey.KeyID;
			SignatureSubPacket sspCreationTime = new SignatureSubPacket();
			sspCreationTime.Type = SignatureSubPacketTypes.SignatureCreationTime;
			sspCreationTime.TimeCreated = DateTime.Now;
			spSign.HashedSubPackets = new SignatureSubPacket[2];
			spSign.HashedSubPackets[0] = sspCreator;
			spSign.HashedSubPackets[1] = sspCreationTime;

			//spSign.KeyID = skpKey.PublicKey.KeyID;
			//spSign.TimeCreated = DateTime.Now;
			spSign.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
			spSign.SignatureType = SignatureTypes.TextSignature;
			spSign.Version = SignaturePacketVersionNumbers.v4;
			
			byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(strMessage);
			spSign.Sign(bMessage, skpKey, strPassphrase);
			
			byte[] bSignature = spSign.Generate();
			
			string strSignature = Radix64.Encode(bSignature, true);
			
			string strFinal;

			if(embedMessage)
				strFinal = Armor.WrapCleartextSignature(strMessage, strSignature);
			else
				strFinal = Armor.WrapCleartextSignature(strSignature);
			
			return strFinal;
		}
		
		/// <summary>
		/// Creates a simmetric encrypted sequence
		/// </summary>
		/// <param name="alKeys">keys to produce the sequence for</param>
		/// <param name="aaAction">encrypt/sign</param>
		/// <param name="saAlgo">algorithm used</param>
		/// <param name="bSymKey">simmetric key</param>
		/// <returns>a simmetric encrypted sequence</returns>
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

		/// <summary>
		/// Retrieves preferences of multiple key about the simmetric algorithm to use
		/// </summary>
		/// <param name="alPublicKeys">list of public keys</param>
		/// <returns>the algorithm to use</returns>
		private static SymAlgorithms GetSymAlgorithmPreferences(ArrayList alPublicKeys) {
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
							} 
							catch (InvalidOperationException) {}
							
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

		/// <summary>
		/// Changes the primary user id of a public key
		/// </summary>
		/// <param name="newPUID">the certified user id to se as primary</param>
		/// <param name="KeyID">the keyID to execute the operation for</param>
		/// <param name="strPassphrase"></param>
		public void changePrimaryUserID(CertifiedUserID newPUID, ulong KeyID, string strPassphrase) {
			TransportablePublicKey tpkKey = this.PublicRing.Find(KeyID,false);
			TransportableSecretKey tskKey = this.SecretRing.Find(KeyID);
			if (tpkKey!=null && tskKey!=null) {
				CertifiedUserID oldPUID = tpkKey.PrimaryUserIDCert;
				if (oldPUID!=newPUID) {
					bool updated = false;
					for (int k = 0; k < oldPUID.Certificates.Count; k++) {
						SignaturePacket sp = (SignaturePacket)oldPUID.Certificates[k];
						if(sp.SignatureType == SignatureTypes.UserIDSignature ||
							sp.SignatureType == SignatureTypes.UserIDSignature_CasualVerification ||
							sp.SignatureType == SignatureTypes.UserIDSignature_NoVerification ||
							sp.SignatureType == SignatureTypes.UserIDSignature_PositivVerification)
						{
							foreach (SignatureSubPacket ssp in sp.HashedSubPackets) {
								if(ssp.Type == SignatureSubPacketTypes.PrimaryUserID) {
									ssp.PrimaryUserID = false;
									updated = true;
								}
							}
							if (!updated) {
								foreach(SignatureSubPacket ssp in sp.UnhashedSubPackets) {
									if(ssp.Type == SignatureSubPacketTypes.PrimaryUserID) {
										ssp.PrimaryUserID = false;
										updated = true;
									}
								}
							}
							if (updated)	{
								oldPUID.Certificates.Remove(sp);
								oldPUID.Sign(sp, tskKey.PrimaryKey, strPassphrase, tpkKey.PrimaryKey);
								break;
							}
						}
					}
					updated = false;
					for (int k = 0; k < oldPUID.Certificates.Count; k++) {
						SignaturePacket sp = (SignaturePacket)newPUID.Certificates[k];
						if (sp.SignatureType == SignatureTypes.UserIDSignature ||
							sp.SignatureType == SignatureTypes.UserIDSignature_CasualVerification ||
							sp.SignatureType == SignatureTypes.UserIDSignature_NoVerification ||
							sp.SignatureType == SignatureTypes.UserIDSignature_PositivVerification)
						{
							foreach(SignatureSubPacket ssp in sp.HashedSubPackets) {
								if(ssp.Type == SignatureSubPacketTypes.PrimaryUserID) {
									ssp.PrimaryUserID = true;
									updated = true;
								}
							}
							if (!updated) {
								foreach (SignatureSubPacket ssp in sp.UnhashedSubPackets) {
									if (ssp.Type == SignatureSubPacketTypes.PrimaryUserID) {
										ssp.PrimaryUserID = true;
										updated = true;
									}
								}
							}
							if (updated) {
								newPUID.Certificates.Remove(sp);
								newPUID.Sign(sp, tskKey.PrimaryKey, strPassphrase, tpkKey.PrimaryKey);
								break;
							}
							if (!updated) {
								SignatureSubPacket sspPrimaryUserID = new SignatureSubPacket();
								sspPrimaryUserID.Type = SignatureSubPacketTypes.PrimaryUserID;
								sspPrimaryUserID.PrimaryUserID = true;
								sp.AddSubPacket(sspPrimaryUserID,true);
								newPUID.Certificates.Remove(sp);
								newPUID.Sign(sp, tskKey.PrimaryKey, strPassphrase, tpkKey.PrimaryKey);
								break;
							}
						}
					}
				}
			}
		}

		/// <summary>
		/// Sets the trust level and amount for a specified userID in a key
		/// </summary>
		/// <param name="userIdKeyId">KeyID of the key containing the userID which this set the trust of</param>
		/// <param name="userID">UserID whose trust has to be set</param>
		/// <param name="KeyID">Signer (Truster) keyID</param>
		/// <param name="strPassphrase">passphrase of the signer</param>
		/// <param name="trustLevel">trust level</param>
		/// <param name="trustAmount">trust amount</param>
		public void setUserIDTrust(ulong userIdKeyId, CertifiedUserID userID, ulong KeyID, string strPassphrase, int trustLevel, int trustAmount) {
			TransportablePublicKey tpkKey = this.PublicRing.Find(userIdKeyId,false);
			TransportableSecretKey tskKey = this.SecretRing.Find(KeyID);
			bool updated = false;
			if (tpkKey!=null && tskKey!=null) {
				ArrayList cert = new ArrayList(userID.Certificates);
				for (int k = 0; k < cert.Count; k++) {
					updated = false;
					SignaturePacket sp = (SignaturePacket)cert[k];
					if ((sp.SignatureType == SignatureTypes.UserIDSignature ||
						sp.SignatureType == SignatureTypes.UserIDSignature_CasualVerification ||
						sp.SignatureType == SignatureTypes.UserIDSignature_NoVerification ||
						sp.SignatureType == SignatureTypes.UserIDSignature_PositivVerification) && sp.KeyID == KeyID)
					{
						foreach (SignatureSubPacket ssp in sp.HashedSubPackets) {
							if(ssp.Type == SignatureSubPacketTypes.TrustSignature) {
								ssp.TrustLevel = (byte)(trustLevel & 0xFF);
								ssp.TrustAmount = (byte)(trustAmount & 0xFF);
								updated = true;
							}
						}
						if (!updated) {
							foreach (SignatureSubPacket ssp in sp.UnhashedSubPackets) {
								if (ssp.Type == SignatureSubPacketTypes.TrustSignature) {
									ssp.TrustLevel = (byte)(trustLevel & 0xFF);
									ssp.TrustAmount = (byte)(trustAmount & 0xFF);
									updated = true;
								}
							}
						}
						if(updated)	{
							userID.Certificates.Remove(sp);
							userID.Sign(sp, tskKey.PrimaryKey, strPassphrase, tpkKey.PrimaryKey);
							updated = true;
						} else {
							SignatureSubPacket sspTrust = new SignatureSubPacket();
							sspTrust.Type = SignatureSubPacketTypes.TrustSignature;
							sspTrust.TrustAmount = (byte)(trustAmount & 0xFF);
							sspTrust.TrustLevel = (byte)(trustLevel & 0xFF);
							sp.AddSubPacket(sspTrust, false);
							userID.Certificates.Remove(sp);
							userID.Sign(sp, tskKey.PrimaryKey, strPassphrase, tpkKey.PrimaryKey);
							updated = true;
						}
					}
				}
			}
			if (!updated)
				throw new Exception("User id not certified by this Key. You cannot set Trust.");
		}

		/// <summary>
		/// Adds a userID to the specified key
		/// </summary>
		/// <param name="userID">user id to be added</param>
		/// <param name="email">user email address</param>
		/// <param name="infos">xml encoded user infos</param>
		/// <param name="strPassphrase">passphrase of the secret key we want to add the user id to</param>
		/// <param name="KeyID">keyID of the key we want to add the userID to</param>
		/// <param name="isRevocable">is a revocable keyID</param>
		public void AddUserID(string userID, string email, string infos, string strPassphrase, ulong KeyID, bool isRevocable) {
			TransportablePublicKey tpkKey = this.PublicRing.Find(KeyID,false);
			TransportableSecretKey tskKey = this.SecretRing.Find(KeyID);
			if (tpkKey != null && tskKey != null) {
				CertifiedUserID cuiUID = new CertifiedUserID();
				UserIDPacket uipUID = new UserIDPacket();
				uipUID.UserID = userID.Trim() + " <" + email.Trim() + ">";
				cuiUID.UserID = uipUID;
			
				SecretKeyPacket skpSignatureKey = tskKey.FindKey(AsymActions.Sign);
				SignaturePacket spSelfSig = new SignaturePacket();
				if (infos != null) {
					SignatureSubPacket sspNotation = new SignatureSubPacket();
					sspNotation.Type = SignatureSubPacketTypes.NotationData;
					sspNotation.NotationName = "PersonalData";
					sspNotation.NotationValue = infos;
					spSelfSig.AddSubPacket(sspNotation,false);
				}
				if (!isRevocable) {
					SignatureSubPacket sspRevocable = new SignatureSubPacket();
					sspRevocable.Type = SignatureSubPacketTypes.Revocable;
					sspRevocable.Revocable = isRevocable;
					spSelfSig.AddSubPacket(sspRevocable, true);
				}
				SignatureSubPacket sspPrimaryUID = new SignatureSubPacket();
				sspPrimaryUID.Type = SignatureSubPacketTypes.PrimaryUserID;
				sspPrimaryUID.Revocable = false;
				spSelfSig.AddSubPacket(sspPrimaryUID, true);

				spSelfSig.Version = SignaturePacketVersionNumbers.v4;
				spSelfSig.HashAlgorithm = HashAlgorithms.SHA1;
				spSelfSig.KeyID = skpSignatureKey.PublicKey.KeyID;
				spSelfSig.TimeCreated = DateTime.Now;
				cuiUID.Certificates = new System.Collections.ArrayList();
				cuiUID.Sign(spSelfSig, skpSignatureKey, strPassphrase, tpkKey.PrimaryKey);
			
				tpkKey.Certifications.Add(cuiUID);
				tskKey.UserIDs.Add(uipUID);
				return;
			}
			throw new Exception("Keys not found");
		}

		private BigInteger[][] GenerateElGamalEncryptionKey(int iKeySize) {
			ElGamal egKeyGenerator = new ElGamal();
			BigInteger[][] biEncryptionKey = egKeyGenerator.Generate(iKeySize);
			return biEncryptionKey;
		}

		private BigInteger[][] GenerateRSAEncryptionKey(int iKeySize) {
			RSA rsaKeyGenerator = new RSA();
			BigInteger[][] biEncryptionKey = rsaKeyGenerator.Generate(iKeySize);
			return biEncryptionKey;
		}
		
		private BigInteger[][] GenerateDSASignatureKey() {
			DSA dDSA = new DSA();
			BigInteger[][] biSignatureKey = dDSA.Generate(1024);
			return biSignatureKey;
		}

		/// <summary>
		/// Generates a subkey for the specified primary key pair
		/// </summary>
		/// <param name="iKeySize">size of the subkey</param>
		/// <param name="strPassphrase">passphrase for the primar secret key</param>
		/// <param name="PrimaryKeyID">primary key pair keyID</param>
		/// <param name="expirationTime">expiration time for the subkey (new DateTime(0) == never)</param>
		/// <param name="isRevocableSubkey">is revocable?</param>
		public void GenerateSubkey(int iKeySize, string strPassphrase, ulong PrimaryKeyID, DateTime expirationTime, bool isRevocableSubkey) {
			if (iKeySize % 1024 != 0)
				throw new Exception("Keysize must be a 1024 multiple");
			TransportablePublicKey tpkKey = this.PublicRing.Find(PrimaryKeyID,false);
			TransportableSecretKey tskKey = this.SecretRing.Find(PrimaryKeyID);
			System.Security.Cryptography.RandomNumberGenerator rngRand;

			BigInteger[][] biEncryptionKey = GenerateElGamalEncryptionKey(iKeySize);

			PublicKeyPacket pkpEncryptionKey = new PublicKeyPacket(true);
			pkpEncryptionKey.Algorithm = AsymAlgorithms.ElGamal_Encrypt_Only;
			pkpEncryptionKey.KeyMaterial = biEncryptionKey[0];
			pkpEncryptionKey.TimeCreated = DateTime.Now;
			pkpEncryptionKey.Version = PublicKeyPacketVersionNumbers.v4;

			SecretKeyPacket skpEncryptionKey = new SecretKeyPacket(true);
			skpEncryptionKey.SymmetricalAlgorithm = SymAlgorithms.AES256;
			skpEncryptionKey.PublicKey = pkpEncryptionKey;
			skpEncryptionKey.InitialVector = new byte[CipherHelper.CipherBlockSize(SymAlgorithms.AES256)];
			rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
			rngRand.GetBytes(skpEncryptionKey.InitialVector);
			skpEncryptionKey.EncryptKeyMaterial(biEncryptionKey[1], strPassphrase);
			skpEncryptionKey.PublicKey = pkpEncryptionKey;

			CertifiedPublicSubkey cpsEncryptionKey = new CertifiedPublicSubkey();
			cpsEncryptionKey.Subkey = pkpEncryptionKey;
			cpsEncryptionKey.SignKeyBindingSignature(tpkKey.PrimaryKey, tskKey.PrimaryKey, strPassphrase, expirationTime, isRevocableSubkey);
			
			tpkKey.SubKeys.Add(cpsEncryptionKey);
			this.PublicRing.AddPublicKey(tpkKey);
					
			tskKey.SubKeys.Add(skpEncryptionKey);
			this.SecretRing.AddSecretKey(tskKey);

		}

		/// <summary>
		/// Generate a key pair
		/// </summary>
		/// <param name="iKeySize">Encription key size</param>
		/// <param name="strPassphrase">passhrase for the key pair</param>
		/// <param name="userID">primary user id</param>
		/// <param name="email">user email</param>
		/// <param name="notation">xml encoded user info</param>
		/// <param name="expirationTime">expiration date of the primary key (new DateTime(0) == never)</param>
		/// <param name="keyType">1: RSA/DSA   0:Elgamal/DSA(DEFAULT)</param>
		/// <param name="isRevocableKey">revocable?</param>
		/// <param name="isRevocableSubkey">revocable subkey?</param>
		public void GenerateKey(int iKeySize, string strPassphrase, string userID, string email, string notation, DateTime expirationTime, int keyType, bool isRevocableKey, bool isRevocableSubkey) {			
			if(iKeySize % 1024 != 0)
				throw new Exception("Keysize must be a 1024 multiple");

			System.Security.Cryptography.RandomNumberGenerator rngRand;
					
			// let's first create the encryption key
			BigInteger[][] biEncryptionKey;
			if (keyType == 1) { 
				// it's a RSA/DSA key
				biEncryptionKey = GenerateRSAEncryptionKey(iKeySize);
			} else { 
				// it's an elgamal/DSA key DEFAULF
				biEncryptionKey = GenerateElGamalEncryptionKey(iKeySize);
			}
					
			// now the signature key
			BigInteger[][] biSignatureKey = GenerateDSASignatureKey();
									
			PublicKeyPacket pkpSignatureKey = new PublicKeyPacket(false);
			pkpSignatureKey.Algorithm = AsymAlgorithms.DSA;
			pkpSignatureKey.KeyMaterial = biSignatureKey[0];
			pkpSignatureKey.TimeCreated = DateTime.Now;
			pkpSignatureKey.Version = PublicKeyPacketVersionNumbers.v4;
					
			SecretKeyPacket skpSignatureKey = new SecretKeyPacket(false);
			skpSignatureKey.SymmetricalAlgorithm = SymAlgorithms.AES256;
			skpSignatureKey.PublicKey = pkpSignatureKey;
			skpSignatureKey.InitialVector = new byte[CipherHelper.CipherBlockSize(SymAlgorithms.AES256)];
			rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
			rngRand.GetBytes(skpSignatureKey.InitialVector);
			skpSignatureKey.EncryptKeyMaterial(biSignatureKey[1], strPassphrase);
			skpSignatureKey.PublicKey = pkpSignatureKey;
					
			PublicKeyPacket pkpEncryptionKey = new PublicKeyPacket(true);
			if (keyType == 0) { 
				// it's an elgamal/DSA key
				pkpEncryptionKey.Algorithm = AsymAlgorithms.ElGamal_Encrypt_Only;
			} else if (keyType == 1) { 
				// it's a RSA/DSA key
				pkpEncryptionKey.Algorithm = AsymAlgorithms.RSA_Encrypt_Only;
			}
			pkpEncryptionKey.KeyMaterial = biEncryptionKey[0];
			pkpEncryptionKey.TimeCreated = DateTime.Now;
			pkpEncryptionKey.Version = PublicKeyPacketVersionNumbers.v4;

			SecretKeyPacket skpEncryptionKey = new SecretKeyPacket(true);
			skpEncryptionKey.SymmetricalAlgorithm = SymAlgorithms.AES256;
			skpEncryptionKey.PublicKey = pkpEncryptionKey;
			skpEncryptionKey.InitialVector = new byte[CipherHelper.CipherBlockSize(SymAlgorithms.AES256)];
			rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
			rngRand.GetBytes(skpEncryptionKey.InitialVector);
			skpEncryptionKey.EncryptKeyMaterial(biEncryptionKey[1], strPassphrase);
			skpEncryptionKey.PublicKey = pkpEncryptionKey;
					
			CertifiedUserID cuiUID = new CertifiedUserID();
			UserIDPacket uipUID = new UserIDPacket();
			uipUID.UserID = userID.Trim() + " <" + email.Trim() + ">";
			cuiUID.UserID = uipUID;
			SignaturePacket spSelfSig = new SignaturePacket();
			if (notation != null) {
				SignatureSubPacket sspNotation = new SignatureSubPacket();
				sspNotation.Type = SignatureSubPacketTypes.NotationData;
				sspNotation.NotationName = "PersonalData";
				sspNotation.NotationValue = notation;
				spSelfSig.AddSubPacket(sspNotation,false);
			}
			if (expirationTime.Ticks != 0) {
				SignatureSubPacket sspExpiration = new SignatureSubPacket();
				sspExpiration.Type = SignatureSubPacketTypes.KeyExpirationTime;
				sspExpiration.KeyExpirationTime = new DateTime(expirationTime.Ticks + (new DateTime(1970,1,2)).Ticks - pkpEncryptionKey.TimeCreated.Ticks);
				spSelfSig.AddSubPacket(sspExpiration, true);
			}
			if (!isRevocableKey) {
				SignatureSubPacket sspRevocable = new SignatureSubPacket();
				sspRevocable.Type = SignatureSubPacketTypes.Revocable;
				sspRevocable.Revocable = isRevocableKey;
				spSelfSig.AddSubPacket(sspRevocable, true);
			}
			SignatureSubPacket sspPrimaryUID = new SignatureSubPacket();
			sspPrimaryUID.Type = SignatureSubPacketTypes.PrimaryUserID;
			sspPrimaryUID.Revocable = true;
			spSelfSig.AddSubPacket(sspPrimaryUID, true);

			spSelfSig.Version = SignaturePacketVersionNumbers.v4;
			spSelfSig.HashAlgorithm = HashAlgorithms.SHA1;
			spSelfSig.KeyID = pkpSignatureKey.KeyID;
			spSelfSig.TimeCreated = DateTime.Now;
			SignatureSubPacket sspPrimaryUserID = new SignatureSubPacket();
			sspPrimaryUserID.Type = SignatureSubPacketTypes.PrimaryUserID;
			sspPrimaryUserID.PrimaryUserID = true;
			spSelfSig.AddSubPacket(sspPrimaryUserID, true);
			SignatureSubPacket sspPreferedSymAlgos = new SignatureSubPacket();
			sspPreferedSymAlgos.Type = SignatureSubPacketTypes.PreferedSymmetricAlgorithms;
			sspPreferedSymAlgos.PreferedSymAlgos = new SymAlgorithms[] {SymAlgorithms.AES256, SymAlgorithms.AES192, SymAlgorithms.AES256, SymAlgorithms.CAST5, SymAlgorithms.Triple_DES};
			spSelfSig.AddSubPacket(sspPreferedSymAlgos, true);
			SignatureSubPacket sspPreferedHashAlgos = new SignatureSubPacket();
			sspPreferedHashAlgos.Type = SignatureSubPacketTypes.PreferedHashAlgorithms;
			sspPreferedHashAlgos.PreferedHashAlgos = new HashAlgorithms[] {HashAlgorithms.SHA1};
			spSelfSig.AddSubPacket(sspPreferedHashAlgos, true);

			cuiUID.Certificates = new System.Collections.ArrayList();
			cuiUID.Sign(spSelfSig, skpSignatureKey, strPassphrase, pkpSignatureKey);
				
			CertifiedPublicSubkey cpsEncryptionKey = new CertifiedPublicSubkey();
			cpsEncryptionKey.Subkey = pkpEncryptionKey;
			cpsEncryptionKey.SignKeyBindingSignature(pkpSignatureKey, skpSignatureKey, strPassphrase, expirationTime, isRevocableSubkey);
				
			TransportablePublicKey tpkPublicKey = new TransportablePublicKey();
			tpkPublicKey.PrimaryKey = pkpSignatureKey;
			tpkPublicKey.SubKeys.Add(cpsEncryptionKey);
			tpkPublicKey.Certifications.Add(cuiUID);
			
			this.PublicRing.AddPublicKey(tpkPublicKey);
				
			TransportableSecretKey tskSecretKey = new TransportableSecretKey();
			tskSecretKey.PrimaryKey = skpSignatureKey;
			tskSecretKey.SubKeys.Add(skpEncryptionKey);
			tskSecretKey.UserIDs.Add(uipUID);

			this.SecretRing.AddSecretKey(tskSecretKey);
		}
				
		/// <summary>
		/// Signs a key 
		/// </summary>
		/// <param name="tspKey">key to be signed</param>
		/// <param name="cuidTobeSigned">user id to be signed</param>
		/// <param name="skpKeySigner">signer private key</param>
		/// <param name="strPassphrase">signer passphrase</param>
		/// <param name="exportable">exportable signature</param>
		/// <param name="expirationTime">expiration time (new DateTime(0) == never)</param>
		/// <param name="isRevocable"></param>
		public void SignKey(TransportablePublicKey tspKey, CertifiedUserID cuidTobeSigned, TransportableSecretKey skpKeySigner, string strPassphrase, bool exportable, DateTime expirationTime, bool isRevocable) {
			SignaturePacket spSig = new SignaturePacket();
			spSig.Version = SignaturePacketVersionNumbers.v4;
			spSig.HashAlgorithm = HashAlgorithms.SHA1;
			spSig.KeyID = skpKeySigner.PrimaryKey.PublicKey.KeyID;
			spSig.TimeCreated = DateTime.Now;
			SignatureSubPacket sspExportableSignature = new SignatureSubPacket();
			sspExportableSignature.Type = SignatureSubPacketTypes.ExportableSignature;
			sspExportableSignature.ExportableSignature = exportable;
			spSig.AddSubPacket(sspExportableSignature, false);
			if (!isRevocable) {
				SignatureSubPacket sspRevocable = new SignatureSubPacket();
				sspRevocable.Type = SignatureSubPacketTypes.Revocable;
				sspRevocable.Revocable = isRevocable;
				spSig.AddSubPacket(sspRevocable, true);
			}	
			if (expirationTime.Ticks != 0) {
				SignatureSubPacket sspExpiration = new SignatureSubPacket();
				sspExpiration.Type = SignatureSubPacketTypes.KeyExpirationTime;
				sspExpiration.KeyExpirationTime = new DateTime(expirationTime.Ticks + (new DateTime(1970,1,2)).Ticks - tspKey.PrimaryKey.TimeCreated.Ticks);
				spSig.AddSubPacket(sspExpiration, true);
			}
			
			cuidTobeSigned.Sign(spSig, skpKeySigner.PrimaryKey, strPassphrase, tspKey.PrimaryKey);
		}

		/// <summary>
		/// Revoke a key
		/// </summary>
		/// <param name="KeyID">key to be revoked</param>
		/// <param name="skpKeySigner">revoker secret key</param>
		/// <param name="strPassphrase">revoker passphrase</param>
		/// <param name="exportable">exportable revocation</param>
		public void RevokeKey(ulong KeyID, TransportableSecretKey skpKeySigner, string strPassphrase, bool exportable) {
			TransportablePublicKey tspKey = this.PublicRing.Find(KeyID,false);
			if (tspKey == null)
				throw new Exception("Public Key not found");
			if (this.PublicRing.isRevoked(KeyID))
				throw new Exception("Public Key alreadyRevoked");
			if (tspKey.PrimaryKey.KeyID !=	KeyID)
				throw new Exception("This is not a Primary key... use Revoke Subkey method instead");

			foreach (SignaturePacket sign in tspKey.PrimaryUserIDCert.Certificates) {	
				if (!sign.isRevocable())
					return;
			}

			bool isRevokerKey = false;
			if (KeyID == skpKeySigner.PrimaryKey.PublicKey.KeyID) {
				isRevokerKey = true;
			} else {
				foreach (SignaturePacket spPacket in tspKey.RevocationKeys) {
					foreach (BigInteger revoker in spPacket.FindRevokerKeys()) {
						if (revoker.ToString() == skpKeySigner.PrimaryKey.PublicKey.Fingerprint.ToString()) {
							isRevokerKey = true;
						}
					}
				}
			}
			if (!isRevokerKey)
				throw new Exception("You cannot revoke this key");

			SignaturePacket spSig = new SignaturePacket();
			spSig.Version = SignaturePacketVersionNumbers.v4;
			spSig.HashAlgorithm = HashAlgorithms.SHA1;
			spSig.KeyID = skpKeySigner.PrimaryKey.PublicKey.KeyID;
			spSig.TimeCreated = DateTime.Now;
			SignatureSubPacket sspExportableSignature = new SignatureSubPacket();
			sspExportableSignature.Type = SignatureSubPacketTypes.ExportableSignature;
			sspExportableSignature.ExportableSignature = exportable;
			spSig.AddSubPacket(sspExportableSignature, false);

			PublicKeyPacket pkpKey = tspKey.PrimaryKey;
			byte[] key = new byte[tspKey.PrimaryKey.Length];
			tspKey.PrimaryKey.Header.CopyTo(key,0);
			tspKey.PrimaryKey.Body.CopyTo(key,tspKey.PrimaryKey.Header.Length);

			spSig.SignatureType = SignatureTypes.KeyRevocationSignature;
			spSig.Sign(key, skpKeySigner.PrimaryKey, strPassphrase);
			tspKey.RevocationSignatures.Add(spSig);
		}
		
		/// <summary>
		/// Revoke a subkey
		/// </summary>
		/// <param name="KeyID">subkey ID</param>
		/// <param name="skpKeySigner">revoker secret key</param>
		/// <param name="strPassphrase">revoker passphrase</param>
		/// <param name="exportable">exportable revocation</param>
		public void RevokeSubKey(ulong KeyID, TransportableSecretKey skpKeySigner, string strPassphrase, bool exportable) {
			TransportablePublicKey tspKey = this.PublicRing.Find(KeyID,false);
			if(tspKey == null)
				throw new Exception("Public Key not found");
			if(tspKey.PrimaryKey.KeyID == KeyID)
				throw new Exception("This is a primary key... use RevokeKey method instead.");

			CertifiedPublicSubkey cps = null;
			foreach(CertifiedPublicSubkey cpsi in tspKey.SubKeys) {
				if(cpsi.Subkey.KeyID == KeyID)
					cps = cpsi;
			}

			bool allowed = false;
			ulong issuer = skpKeySigner.PrimaryKey.PublicKey.KeyID;
			if(issuer == tspKey.PrimaryKey.KeyID) {
				allowed = true;
			} else {
				foreach (SignaturePacket spPacket in tspKey.RevocationKeys) {
					foreach (BigInteger revoker in spPacket.FindRevokerKeys()) {
						if (revoker.ToString() == skpKeySigner.PrimaryKey.PublicKey.Fingerprint.ToString()) {
							allowed = true;
						}
					}
				}
			}
			
			if (allowed && cps.KeyBindingSignature.isRevocable()) {
				if (this.PublicRing.isRevoked(KeyID))
					throw new Exception("Public SubKey alreadyRevoked");

				SignaturePacket spSig = new SignaturePacket();
				spSig.Version = SignaturePacketVersionNumbers.v4;
				spSig.HashAlgorithm = HashAlgorithms.SHA1;
				spSig.KeyID = skpKeySigner.PrimaryKey.PublicKey.KeyID;
				spSig.TimeCreated = DateTime.Now;
				SignatureSubPacket sspExportableSignature = new SignatureSubPacket();
				sspExportableSignature.Type = SignatureSubPacketTypes.ExportableSignature;
				sspExportableSignature.ExportableSignature = exportable;
				spSig.AddSubPacket(sspExportableSignature, false);

				byte[] subkey = new byte[cps.Subkey.Length];
				cps.Subkey.Header.CopyTo(subkey,0);
				cps.Subkey.Body.CopyTo(subkey,cps.Subkey.Header.Length);
				subkey[0]=0x99;

				byte[] mainkey = new byte[tspKey.PrimaryKey.Length];
				tspKey.PrimaryKey.Header.CopyTo(mainkey,0);
				tspKey.PrimaryKey.Body.CopyTo(mainkey,tspKey.PrimaryKey.Header.Length);

				byte[] key = new byte[subkey.Length+mainkey.Length];
				mainkey.CopyTo(key,0);
				subkey.CopyTo(key,mainkey.Length);

				spSig.SignatureType = SignatureTypes.SubkeyRevocationSignature;
				spSig.Sign(key, skpKeySigner.PrimaryKey, strPassphrase);
				cps.RevocationSignature=spSig;
			} else 
				throw new Exception("Not allowed to revoke this subkey");
		}
		
		/// <summary>
		/// Revokes a key certified userID
		/// </summary>
		/// <param name="KeyID">key containing the certified user id</param>
		/// <param name="cuidTobeSigned">certified user id to be revoked</param>
		/// <param name="skpKeySigner">revoker secret key</param>
		/// <param name="strPassphrase">revoker passphrase</param>
		/// <param name="exportable">exportable revocation</param>
		public void RevokeKeyCertificate(ulong KeyID, CertifiedUserID cuidTobeSigned, TransportableSecretKey skpKeySigner, string strPassphrase, bool exportable) {
			TransportablePublicKey tspKey = this.PublicRing.Find(KeyID,false);
			if(tspKey == null)
				throw new Exception("Public Key not found");
			bool found = false;
			CertifiedUserID toBeVerified = null;
			foreach(CertifiedUserID cui in tspKey.Certifications) {
				if(cui==cuidTobeSigned) {
					found=true;
					toBeVerified = cui;
					break;
				}
			}
			if (!found)
				throw new Exception("UserId not found among Key certificates");

			found = false;
			foreach(SignaturePacket sign in toBeVerified.Certificates) {	
				if(sign.KeyID == skpKeySigner.PrimaryKey.PublicKey.KeyID && sign.isRevocable())
					found = true;
			}
			if (!found)
				throw new Exception("UserId not certified by this private key or not revocable");

			SignaturePacket spSig = new SignaturePacket();
			spSig.Version = SignaturePacketVersionNumbers.v4;
			spSig.HashAlgorithm = HashAlgorithms.SHA1;
			spSig.KeyID = skpKeySigner.PrimaryKey.PublicKey.KeyID;
			spSig.TimeCreated = DateTime.Now;
			SignatureSubPacket sspExportableSignature = new SignatureSubPacket();
			sspExportableSignature.Type = SignatureSubPacketTypes.ExportableSignature;
			sspExportableSignature.ExportableSignature = exportable;
			spSig.AddSubPacket(sspExportableSignature, false);
			cuidTobeSigned.Revoke(spSig, skpKeySigner.PrimaryKey, strPassphrase, tspKey.PrimaryKey);
		}
	}
}

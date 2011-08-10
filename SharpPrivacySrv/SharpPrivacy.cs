// created on 14.06.2003 at 19:05
using System;
using System.Xml;
using System.IO;
using System.Collections;
using System.Diagnostics;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Security.Principal;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacySrv {
	
	public class SharpPrivacy : System.MarshalByRefObject, SharpPrivacyIF.ISharpPrivacyIF {
		
		private SharpPrivacyLib.PublicKeyRing pkrKeyRing = null;
		private SharpPrivacyLib.SecretKeyRing skrKeyRing = null;
		private string strPublicKeyringPath = "";
		private string strSecretKeyringPath = "";
		
		public void SetKeyringPath(string strPublicPath, string strSecretPath) {
			if (pkrKeyRing == null)
				pkrKeyRing = new SharpPrivacyLib.PublicKeyRing();
			
			if (skrKeyRing == null)
				skrKeyRing = new SharpPrivacyLib.SecretKeyRing();
			
			if (strPublicKeyringPath.ToUpper() != strPublicPath.ToUpper()) {
				pkrKeyRing.Load(strPublicPath);
				strPublicKeyringPath = strPublicPath;
			}
			
			if (strSecretKeyringPath.ToLower() != strSecretPath.ToUpper()) {
				skrKeyRing.Load(strSecretPath);
				strSecretKeyringPath = strSecretPath;
			}
		}
		
		public string EncryptText(string strMessage, ulong[] lTargetKeyIDs) {
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
			lmMessage.Text = strMessage;
			lmMessage.TimeCreated = DateTime.Now;
			lmMessage.Filename = "";
			
			byte[] bReturn = EncryptMessage(lmMessage, lTargetKeyIDs);
			
			string strReturn = Radix64.Encode(bReturn, true);
			
			strReturn = Armor.WrapMessage(strReturn);
			
			return strReturn;
		}
		
		public void EncryptFile(string strPath, string strOutput, ulong[] lTargetKeyIDs) {
			TransportablePublicKey[] tpkSelectedKeys = new TransportablePublicKey[lTargetKeyIDs.Length];
			for (int i=0; i<lTargetKeyIDs.Length; i++) 
				tpkSelectedKeys[i] = pkrKeyRing.Find(lTargetKeyIDs[i], true);
			
			System.IO.FileStream fsFile = new FileStream(strPath, FileMode.Open);
			BinaryReader brReader = new BinaryReader(fsFile);
			byte[] bFileContent = brReader.ReadBytes((int)fsFile.Length);
			brReader.Close();
			fsFile.Close();
			
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
			lmMessage.Binary = bFileContent;
			lmMessage.TimeCreated = DateTime.Now;
			int iLastBackslash = strPath.LastIndexOf("\\");
			lmMessage.Filename = strPath.Substring(iLastBackslash + 1, strPath.Length - iLastBackslash - 1);
			
			byte[] bReturn = EncryptMessage(lmMessage, lTargetKeyIDs);
			
			FileStream fsOut = new FileStream(strOutput, FileMode.CreateNew);
			BinaryWriter bwWrite = new BinaryWriter(fsOut);
			
			bwWrite.Write(bReturn);
			bwWrite.Close();
			fsOut.Close();
		}
		
		
		public string EncryptAndSignText(string strMessage, ulong[] lTargetKeyIDs, ulong lSignatureKeyID, string strPassphrase) {
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Text);
			lmMessage.Text = strMessage;
			lmMessage.TimeCreated = DateTime.Now;
			lmMessage.Filename = "";
			
			SignedMessage smMessage = this.SignMessage(lmMessage, lSignatureKeyID, strPassphrase);
			byte[] bReturn = EncryptMessage(smMessage, lTargetKeyIDs);
			
			string strReturn = Radix64.Encode(bReturn, true);
			
			strReturn = Armor.WrapMessage(strReturn);
			
			return strReturn;
		}
		
		public void EncryptAndSignFile(string strPath, string strOutput, ulong[] lTargetKeyIDs, ulong lSignatureKeyID, string strPassphrase) {
			TransportablePublicKey[] tpkSelectedKeys = new TransportablePublicKey[lTargetKeyIDs.Length];
			for (int i=0; i<lTargetKeyIDs.Length; i++) 
				tpkSelectedKeys[i] = pkrKeyRing.Find(lTargetKeyIDs[i], true);
			
			System.IO.FileStream fsFile = new FileStream(strPath, FileMode.Open);
			BinaryReader brReader = new BinaryReader(fsFile);
			byte[] bFileContent = brReader.ReadBytes((int)fsFile.Length);
			brReader.Close();
			fsFile.Close();
			
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
			lmMessage.Binary = bFileContent;
			lmMessage.TimeCreated = DateTime.Now;
			int iLastBackslash = strPath.LastIndexOf("\\");
			lmMessage.Filename = strPath.Substring(iLastBackslash + 1, strPath.Length - iLastBackslash - 1);
			
			SignedMessage smMessage = SignMessage(lmMessage, lSignatureKeyID, strPassphrase);
			byte[] bReturn = EncryptMessage(smMessage, lTargetKeyIDs);
			
			FileStream fsOut = new FileStream(strOutput, FileMode.CreateNew);
			BinaryWriter bwWrite = new BinaryWriter(fsOut);
			
			bwWrite.Write(bReturn);
			bwWrite.Close();
			fsOut.Close();
		}
		
		public void DeletePublicKey(ulong lKeyID) {
			pkrKeyRing.Delete(lKeyID);
			pkrKeyRing.Save();
		}
		
		
		public string SignText(string strMessage, ulong lSignatureKeyID, string strPassphrase) {
			SignaturePacket spSign = new SignaturePacket();
			
			strMessage = Radix64.TrimMessage(strMessage);
			
			TransportableSecretKey tskKey = skrKeyRing.Find(lSignatureKeyID);
			SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
			
			spSign.HashAlgorithm = HashAlgorithms.SHA1;
			spSign.Format = PacketFormats.New;
			spSign.KeyID = skpKey.PublicKey.KeyID;
			spSign.TimeCreated = DateTime.Now;
			spSign.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
			spSign.SignatureType = SignatureTypes.TextSignature;
			spSign.Version = SignaturePacketVersionNumbers.v4;
			
			byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(strMessage);
			spSign.Sign(bMessage, skpKey, strPassphrase);
			byte[] bSignature = spSign.Generate();
			string strSignature = Radix64.Encode(bSignature, true);
			string strFinal = Armor.WrapCleartextSignature(strMessage, strSignature);
			
			return strFinal;
		}
		
		public void SignFile(string strPath, string strOutput, ulong lSignatureKeyID, string strPassphrase) {
			System.IO.FileStream fsFile = new FileStream(strPath, FileMode.Open);
			BinaryReader brReader = new BinaryReader(fsFile);
			byte[] bFileContent = brReader.ReadBytes((int)fsFile.Length);
			brReader.Close();
			fsFile.Close();
			
			LiteralMessage lmMessage = new LiteralMessage(DataFormatTypes.Binary);
			lmMessage.Binary = bFileContent;
			lmMessage.TimeCreated = DateTime.Now;
			int iLastBackslash = strPath.LastIndexOf("\\");
			lmMessage.Filename = strPath.Substring(iLastBackslash + 1, strPath.Length - iLastBackslash - 1);
			
			SignedMessage smMessage = SignMessage(lmMessage, lSignatureKeyID, strPassphrase);
			byte[] bReturn = smMessage.GetEncoded();
			
			FileStream fsOut = new FileStream(strOutput, FileMode.CreateNew);
			BinaryWriter bwWrite = new BinaryWriter(fsOut);
			
			bwWrite.Write(bReturn);
			bwWrite.Close();
			fsOut.Close();
		}
		
		
		public ulong GetDecryptionKey(string strMessage) {
			ArmorTypes atType = new ArmorTypes();
			string strRest = "";
			string strRadix64 = Armor.RemoveArmor(strMessage, ref atType, ref strRest);
			if (strRadix64.Length == 0)
				throw new Exception("This is not a valid OpenPGP message!");
			
			EncryptedMessage emMessage = new EncryptedMessage();
			Packet[] pPackets = Packet.ParsePackets(strRadix64);
			
			emMessage.ParseMessage(pPackets);
				
			if (!emMessage.SymmetricallyEncrypted) {
				ulong lKeyID = emMessage.GetFittingKeyID(skrKeyRing);
				return lKeyID;
			} else
				return 0ul;
		}
		
		public ulong GetDecryptionKeyFromFile(string strPath) {
			System.IO.FileStream fsIn = new FileStream(strPath, FileMode.Open);
			System.IO.BinaryReader brIn = new BinaryReader(fsIn);
			
			byte[] bData = new byte[fsIn.Length];
			brIn.Read(bData, 0, bData.Length);
			
			try {
				string strMessage = System.Text.Encoding.UTF8.GetString(bData);
				return GetDecryptionKey(strMessage);
			} catch (Exception) {
				EncryptedMessage emMessage = new EncryptedMessage();
				Packet[] pPackets = Packet.ParsePackets(bData);
				
				emMessage.ParseMessage(pPackets);
					
				if (!emMessage.SymmetricallyEncrypted)
					return emMessage.GetFittingKeyID(skrKeyRing);
				else
					return 0ul;
			}
		}
		
		public string DecryptAndVerify(string strMessage, string strPassphrase) {
			
			ArmorTypes atType = new ArmorTypes();
			string strRest = "";
			string strRadix64 = Armor.RemoveArmor(strMessage, ref atType, ref strRest);
			if (strRadix64.Length == 0)
				throw new Exception("This is not a valid OpenPGP message!");
			
			return this.DecryptAndVerifyData(Radix64.Decode(strRadix64), strPassphrase);
		}
		
		public string DecryptAndVerifyFile(string strPath, string strPassphrase) {
			System.IO.FileStream fsIn = new FileStream(strPath, FileMode.Open);
			System.IO.BinaryReader brIn = new BinaryReader(fsIn);
			
			byte[] bData = new byte[fsIn.Length];
			brIn.Read(bData, 0, bData.Length);
			
			string strReturn;
			try {
				string strMessage = System.Text.Encoding.UTF8.GetString(bData);
				strReturn = DecryptAndVerify(strMessage, strPassphrase);
			} catch (Exception) {
				return DecryptAndVerifyData(bData, strPassphrase);
			}
			
			return strReturn;
			
		}
		
		public void RemovePublicKey(ulong lKeyID) {
			pkrKeyRing.Delete(lKeyID);
			pkrKeyRing.Save();
		}
		
		public void RemoveSecretKey(ulong lKeyID) {
			skrKeyRing.Delete(lKeyID);
			skrKeyRing.Save();
		}
		
		public void AddKey(string strKey) {
			bool bNotImported = false;
			bool bError = false;
			
			string strRest = "";
			ArmorTypes atType = new ArmorTypes();
			do {
				strKey = Armor.RemoveArmor(strKey, ref atType, ref strRest);
				if (atType == ArmorTypes.PrivateKeyBlock) {
					try {
						TransportableSecretKey[] tskKeys = TransportableSecretKey.SplitKeys(strKey);
						for (int i=0; i<tskKeys.Length; i++) {
							TransportableSecretKey tskKey = tskKeys[i];
							TransportableSecretKey tskTestKey = skrKeyRing.Find(tskKey.PrimaryKey.PublicKey.KeyID);
							if (tskTestKey != null) {
								bNotImported = true;
								continue;
							}
							skrKeyRing.AddSecretKey(tskKey);
						}
					} catch (Exception) {
						bError = true;
					}
				} else if (atType == ArmorTypes.PublicKeyBlock) {
					try {
						TransportablePublicKey[] tpkKeys = TransportablePublicKey.SplitKeys(strKey);
						for (int i=0; i<tpkKeys.Length; i++) {
							TransportablePublicKey tpkKey = tpkKeys[i];
							TransportablePublicKey tpkTestKey = pkrKeyRing.Find(tpkKey.PrimaryKey.KeyID, true);
							if (tpkTestKey != null) {
								bNotImported = true;
								continue;
							}
							pkrKeyRing.AddPublicKey(tpkKey);
						}
					} catch (Exception) {
						bError = true;
					}
				}
				strKey = strRest;
			} while (strKey.Length > 0);
			
			pkrKeyRing.Save();
			skrKeyRing.Save();
			
			if (bError)
				throw new Exception("Some keys could not be imported, because there were errors!");
			
			if (bNotImported)
				throw new Exception("Some keys could not be imported, because they were already in your keyring!");
		}
		
		public string GetPublicKeysProperties() {
			string strReturn = "<PublicKeyRing>";
			
			
			IEnumerator ieKeys = pkrKeyRing.PublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportablePublicKey))
					continue;
				
				TransportablePublicKey tpkKey = (TransportablePublicKey)ieKeys.Current;
				strReturn += "\n" + GetPublicKeyProperties(tpkKey.PrimaryKey.KeyID);
			}
			
			return strReturn + "</PublicKeyRing>";
		}
		
		public string GetPublicKeyProperties(ulong lKeyID) {
			TransportablePublicKey tpkKey = pkrKeyRing.Find(lKeyID, false);
			
			XmlDocument xmlDoc = new XmlDocument();
			
			XmlElement xmlPublicKey = xmlDoc.CreateElement("PublicKey");
			xmlPublicKey.SetAttribute("keyid", "0x" + tpkKey.PrimaryKey.KeyID.ToString("x"));
			xmlPublicKey.SetAttribute("fingerprint", tpkKey.PrimaryKey.Fingerprint.ToString(16));
			xmlPublicKey.SetAttribute("created", tpkKey.PrimaryKey.TimeCreated.Ticks.ToString());
			try {
				xmlPublicKey.SetAttribute("expiration", tpkKey.KeyExpirationTime.Ticks.ToString());
			} catch (System.Exception) {
				xmlPublicKey.SetAttribute("expiration", "never");
			}
			xmlPublicKey.SetAttribute("size" , tpkKey.PrimaryKey.KeyMaterial[0].bitCount().ToString());
			xmlPublicKey.SetAttribute("algorithm", tpkKey.PrimaryKey.Algorithm.ToString());
			
			XmlElement xmlUserIDs = xmlDoc.CreateElement("UserIDs");
			
			XmlElement xmlUserID;
			
			IEnumerator ieUserIDs = tpkKey.Certifications.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				if (!(ieUserIDs.Current is CertifiedUserID))
					continue;
				
				CertifiedUserID cuiUID = (CertifiedUserID)ieUserIDs.Current;
				cuiUID.Validate(tpkKey.PrimaryKey, pkrKeyRing);
				
				xmlUserID = xmlDoc.CreateElement("UserID");
				xmlUserID.SetAttribute("name", cuiUID.UserID.UserID);
				string strPrimary = "false";
				if (tpkKey.PrimaryUserID == cuiUID.UserID.UserID)
					strPrimary = "true";
				
				xmlUserID.SetAttribute("primary", strPrimary);
				
				DateTime dtTimeCreated = DateTime.Now;
				XmlElement xmlSignature;
				IEnumerator ieSignatures = cuiUID.Certificates.GetEnumerator();
				while (ieSignatures.MoveNext()) {
					if (!(ieSignatures.Current is SignaturePacket))
						continue;
					
					SignaturePacket spSignature = (SignaturePacket)ieSignatures.Current;
					xmlSignature = xmlDoc.CreateElement("Signature");
					xmlSignature.SetAttribute("keyid", "0x" + spSignature.KeyID.ToString("x"));
					xmlSignature.SetAttribute("created", spSignature.TimeCreated.Ticks.ToString());
					string strExpiration = "";
					try {
						strExpiration = spSignature.FindExpirationTime().Ticks.ToString();
					} catch (InvalidOperationException) {
						strExpiration = "never";
					}
					xmlSignature.SetAttribute("expiration", strExpiration);
					xmlSignature.SetAttribute("signaturestatus", spSignature.SignatureStatus.ToString());
					
					string strCreator = "";
					try {
						TransportablePublicKey tpkSignatureKey = pkrKeyRing.Find(spSignature.KeyID, false);
						strCreator = tpkSignatureKey.PrimaryUserID;
					} catch (Exception) {
						strCreator = "0x" + spSignature.KeyID.ToString("x");
					}
					xmlSignature.SetAttribute("creator", strCreator);
					xmlSignature.SetAttribute("algorithm", spSignature.SignatureAlgorithm.ToString());
					if (spSignature.KeyID == tpkKey.PrimaryKey.KeyID)
						dtTimeCreated = spSignature.TimeCreated;
					
					xmlUserID.AppendChild(xmlSignature);
					
				}
				xmlUserID.SetAttribute("created", dtTimeCreated.Ticks.ToString());
				
				xmlUserIDs.AppendChild(xmlUserID);
				
			}
			xmlPublicKey.AppendChild(xmlUserIDs);
			
			XmlElement xmlSubkeys = xmlDoc.CreateElement("Subkeys");
			
			XmlElement xmlSubkey;
			IEnumerator ieSubkeys = tpkKey.SubKeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (!(ieSubkeys.Current is CertifiedPublicSubkey))
					continue;
				
				CertifiedPublicSubkey cpsSubkey = (CertifiedPublicSubkey)ieSubkeys.Current;
				
				xmlSubkey = xmlDoc.CreateElement("Subkey");
				xmlSubkey.SetAttribute("keyid", "0x" + cpsSubkey.Subkey.KeyID.ToString("x"));
				xmlSubkey.SetAttribute("fingerprint", cpsSubkey.Subkey.Fingerprint.ToString(16));
				xmlSubkey.SetAttribute("created", cpsSubkey.Subkey.TimeCreated.Ticks.ToString());
				
				string strExpiration = "";
				try {
					strExpiration = cpsSubkey.KeyBindingSignature.FindExpirationTime().Ticks.ToString();
				} catch (InvalidOperationException) {
					strExpiration = "never";
				}
				xmlSubkey.SetAttribute("expiration", strExpiration);				
				xmlSubkey.SetAttribute("size", cpsSubkey.Subkey.KeyMaterial[0].bitCount().ToString());
				xmlSubkey.SetAttribute("algorithm", cpsSubkey.Subkey.Algorithm.ToString());
				
				xmlSubkeys.AppendChild(xmlSubkey);
			}
			
			xmlPublicKey.AppendChild(xmlSubkeys);
			xmlDoc.AppendChild(xmlPublicKey);
			return xmlDoc.OuterXml;
		}
		
		
		public string GetSecretKeysProperties() {
			string strReturn = "<SecretKeyRing>";
			
			
			IEnumerator ieKeys = skrKeyRing.SecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportableSecretKey))
					continue;
				
				TransportableSecretKey tskKey = (TransportableSecretKey)ieKeys.Current;
				strReturn += "\n" + GetSecretKeyProperties(tskKey.PrimaryKey.PublicKey.KeyID);
			}
			
			return strReturn + "</SecretKeyRing>";
		}
		
		public string GetSecretKeyProperties(ulong lKeyID) {
			TransportableSecretKey tskKey = skrKeyRing.Find(lKeyID);
			SecretKeyPacket skpKey = tskKey.PrimaryKey;
			
			XmlDocument xmlDoc = new XmlDocument();
			
			XmlElement xmlSecretKey = xmlDoc.CreateElement("SecretKey");
			xmlSecretKey.SetAttribute("keyid", "0x" + skpKey.PublicKey.KeyID.ToString("x"));
			xmlSecretKey.SetAttribute("fingerprint", skpKey.PublicKey.Fingerprint.ToString(16));
			xmlSecretKey.SetAttribute("size", skpKey.PublicKey.KeyMaterial[0].bitCount().ToString());
			xmlSecretKey.SetAttribute("algorithm", skpKey.PublicKey.Algorithm.ToString());
			xmlSecretKey.SetAttribute("timecreated", skpKey.PublicKey.TimeCreated.Ticks.ToString());
			
			XmlElement xmlUserIDs = xmlDoc.CreateElement("UserIDs");
			
			XmlElement xmlUserID;
			IEnumerator ieUserIDs = tskKey.UserIDs.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				if (!(ieUserIDs.Current is UserIDPacket))
					continue;
				
				UserIDPacket uipUID = (UserIDPacket)ieUserIDs.Current;
				xmlUserID = xmlDoc.CreateElement("UserID");
				xmlUserID.SetAttribute("name", uipUID.UserID);
				
				xmlUserIDs.AppendChild(xmlUserID);
				
			}
			
			xmlSecretKey.AppendChild(xmlUserIDs);
			
			XmlElement xmlSubkeys = xmlDoc.CreateElement("Subkeys");
			
			XmlElement xmlSubkey;
			IEnumerator ieSubkeys = tskKey.SubKeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (!(ieSubkeys.Current is SecretKeyPacket))
					continue;
				
				SecretKeyPacket skpSubkey = (SecretKeyPacket)ieSubkeys.Current;
				xmlSubkey = xmlDoc.CreateElement("Subkey");
				xmlSubkey.SetAttribute("keyid", "0x" + skpSubkey.PublicKey.KeyID.ToString("x"));
				xmlSubkey.SetAttribute("fingerprint", skpSubkey.PublicKey.Fingerprint.ToString(16));
				xmlSubkey.SetAttribute("size", skpSubkey.PublicKey.KeyMaterial[0].bitCount().ToString());
				xmlSubkey.SetAttribute("algorithm", skpSubkey.PublicKey.Algorithm.ToString());
				
				
				xmlSubkeys.AppendChild(xmlSubkey);
				
			}
			
			xmlSecretKey.AppendChild(xmlSubkeys);
			
			xmlDoc.AppendChild(xmlSecretKey);
			
			return xmlDoc.OuterXml;
		}
		
		public string GetPublicKey(ulong lKeyID) {
			TransportablePublicKey tpkKey = pkrKeyRing.Find(lKeyID, true);
			byte[] bKey = tpkKey.Generate();
			return Armor.WrapPublicKey(bKey);
		}
		
		public string GetSecretKey(ulong lKeyID, string strPassphrase) {
			TransportableSecretKey tskKey = skrKeyRing.Find(lKeyID);
			tskKey.PrimaryKey.GetDecryptedKeyMaterial(strPassphrase);
			
			byte[] bKey = tskKey.Generate();
			return Armor.WrapPrivateKey(bKey);
		}
		
		private BigInteger[][] GenerateEncryptionKey(int iKeySize) {
			ElGamal egKeyGenerator = new ElGamal();
			
			return egKeyGenerator.Generate(iKeySize);
		}
		
		private BigInteger[][] GenerateSignatureKey() {
			DSA dDSA = new DSA();
			
			return dDSA.Generate(1024);
		}
		
		public void AddUserID(ulong lKeyID, string strName, string strEmail, string strPassphrase) {
			TransportableSecretKey tskKey = skrKeyRing.Find(lKeyID);
			TransportablePublicKey tpkKey = pkrKeyRing.Find(lKeyID, false);
			
			CertifiedUserID cuiUID = new CertifiedUserID();
			UserIDPacket uipUID = new UserIDPacket();
			uipUID.UserID = strName.Trim() + " <" + strEmail.Trim() + ">";
			cuiUID.UserID = uipUID;
			
			SecretKeyPacket skpSignatureKey = tskKey.FindKey(AsymActions.Sign);
			SignaturePacket spSelfSig = new SignaturePacket();
			spSelfSig.Version = SignaturePacketVersionNumbers.v4;
			spSelfSig.HashAlgorithm = HashAlgorithms.SHA1;
			spSelfSig.KeyID = skpSignatureKey.PublicKey.KeyID;
			spSelfSig.TimeCreated = DateTime.Now;
			cuiUID.Certificates = new System.Collections.ArrayList();
			cuiUID.Sign(spSelfSig, skpSignatureKey, strPassphrase, tpkKey.PrimaryKey);
			
			tpkKey.Certifications.Add(cuiUID);
			tskKey.UserIDs.Add(uipUID);
		}
		
		public void SignKey(ulong lSignedKeyID, ulong lSigningKeyID, string strUserID, int nIntroducerDepth, bool bIsExportable, int nType, string strPassphrase) {
			TransportableSecretKey tskKey = skrKeyRing.Find(lSigningKeyID);
			SecretKeyPacket skpSignatureKey = tskKey.FindKey(AsymActions.Sign);
			
			TransportablePublicKey tpkKey = pkrKeyRing.Find(lSignedKeyID, false);
			
			SignaturePacket spCertificate = new SignaturePacket();
			spCertificate.SignatureType = (SignatureTypes)nType;
			spCertificate.Version = SignaturePacketVersionNumbers.v4;
			spCertificate.HashAlgorithm = HashAlgorithms.SHA1;
			spCertificate.KeyID = skpSignatureKey.PublicKey.KeyID;
			spCertificate.TimeCreated = DateTime.Now;
			
			CertifiedUserID cuiID = null;
			IEnumerator ieUserIDs = tpkKey.Certifications.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				if (!(ieUserIDs.Current is CertifiedUserID))
					continue;
				
				CertifiedUserID cuiThisID = (CertifiedUserID)ieUserIDs.Current;
				if (cuiThisID.ToString() == strUserID) {
					cuiID = cuiThisID;
				}
			}
			if (cuiID == null)
				throw new Exception("UserID could not be found!");
			
			if (bIsExportable == false) {
				SignatureSubPacket sspNotExportable = new SignatureSubPacket();
				sspNotExportable.Type = SignatureSubPacketTypes.ExportableSignature;
				sspNotExportable.ExportableSignature = false;
				spCertificate.AddSubPacket(sspNotExportable, true);
			}
			
			if (nIntroducerDepth > 0) {
				SignatureSubPacket sspTrust = new SignatureSubPacket();
				sspTrust.Type = SignatureSubPacketTypes.TrustSignature;
				sspTrust.TrustLevel = (byte)nIntroducerDepth;
				sspTrust.TrustAmount = 120;
				spCertificate.AddSubPacket(sspTrust, true);
			}
			
			cuiID.Sign(spCertificate, skpSignatureKey, strPassphrase, tpkKey.PrimaryKey);
			tpkKey.Certifications.Remove(cuiID);
			tpkKey.Certifications.Add(cuiID);
			
			pkrKeyRing.Delete(lSignedKeyID);
			pkrKeyRing.AddPublicKey(tpkKey);
			pkrKeyRing.Save();
		}
		
		public void GenerateKey(string strName, string strEmail, string strKeyType, int iKeySize, long lExpiration, string strPassphrase) {
			if (strKeyType == "ElGamal/DSA") {
				System.Security.Cryptography.RandomNumberGenerator rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
				
				// let's first create the encryption key
				BigInteger[][] biEncryptionKey = GenerateEncryptionKey(iKeySize);
				
				// now the signature key
				BigInteger[][] biSignatureKey = GenerateSignatureKey();
				
				PublicKeyPacket pkpSignatureKey = new PublicKeyPacket(false);
				pkpSignatureKey.Algorithm = AsymAlgorithms.DSA;
				pkpSignatureKey.KeyMaterial = biSignatureKey[0];
				pkpSignatureKey.TimeCreated = DateTime.Now;
				pkpSignatureKey.Version = PublicKeyPacketVersionNumbers.v4;
				
				SecretKeyPacket skpSignatureKey = new SecretKeyPacket(false);
				skpSignatureKey.SymmetricalAlgorithm = SymAlgorithms.AES256;
				skpSignatureKey.PublicKey = pkpSignatureKey;
				skpSignatureKey.InitialVector = new byte[CipherHelper.CipherBlockSize(SymAlgorithms.AES256)];
				rngRand.GetBytes(skpSignatureKey.InitialVector);
				skpSignatureKey.EncryptKeyMaterial(biSignatureKey[1], strPassphrase);
				skpSignatureKey.PublicKey = pkpSignatureKey;
				
				PublicKeyPacket pkpEncryptionKey = new PublicKeyPacket(true);
				pkpEncryptionKey.Algorithm = AsymAlgorithms.ElGamal_Encrypt_Only;
				pkpEncryptionKey.KeyMaterial = biEncryptionKey[0];
				pkpEncryptionKey.TimeCreated = DateTime.Now;
				pkpEncryptionKey.Version = PublicKeyPacketVersionNumbers.v4;

				SecretKeyPacket skpEncryptionKey = new SecretKeyPacket(true);
				skpEncryptionKey.SymmetricalAlgorithm = SymAlgorithms.AES256;
				skpEncryptionKey.PublicKey = pkpEncryptionKey;
				skpEncryptionKey.InitialVector = new byte[CipherHelper.CipherBlockSize(SymAlgorithms.AES256)];
				rngRand.GetBytes(skpEncryptionKey.InitialVector);
				skpEncryptionKey.EncryptKeyMaterial(biEncryptionKey[1], strPassphrase);
				skpEncryptionKey.PublicKey = pkpEncryptionKey;
				
				CertifiedUserID cuiUID = new CertifiedUserID();
				UserIDPacket uipUID = new UserIDPacket();
				uipUID.UserID = strName.Trim() + " <" + strEmail.Trim() + ">";
				cuiUID.UserID = uipUID;
				SignaturePacket spSelfSig = new SignaturePacket();
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
				if (lExpiration != 0) {
					SignatureSubPacket sspExpiration = new SignatureSubPacket();
					sspExpiration.Type = SignatureSubPacketTypes.SignatureExpirationTime;
					sspExpiration.SignatureExpirationTime = new DateTime(lExpiration);
					spSelfSig.AddSubPacket(sspExpiration, true);
				}
				cuiUID.Certificates = new System.Collections.ArrayList();
				cuiUID.Sign(spSelfSig, skpSignatureKey, strPassphrase, pkpSignatureKey);
				
				CertifiedPublicSubkey cpsEncryptionKey = new CertifiedPublicSubkey();
				cpsEncryptionKey.Subkey = pkpEncryptionKey;
				cpsEncryptionKey.SignKeyBindingSignature(pkpSignatureKey, skpSignatureKey, strPassphrase, new DateTime(lExpiration), true);
				
				TransportablePublicKey tpkPublicKey = new TransportablePublicKey();
				tpkPublicKey.PrimaryKey = pkpSignatureKey;
				tpkPublicKey.SubKeys.Add(cpsEncryptionKey);
				tpkPublicKey.Certifications.Add(cuiUID);
				
				TransportableSecretKey tskSecretKey = new TransportableSecretKey();
				tskSecretKey.PrimaryKey = skpSignatureKey;
				tskSecretKey.SubKeys.Add(skpEncryptionKey);
				tskSecretKey.UserIDs.Add(uipUID);
				
				this.pkrKeyRing.AddPublicKey(tpkPublicKey);
				this.skrKeyRing.AddSecretKey(tskSecretKey);
				pkrKeyRing.Save();
				skrKeyRing.Save();
				
			// it's an RSA key
			} else if (strKeyType == "RSA") {
				
			}
		}
		
		private SymAlgorithms GetSymAlgorithmPreferences(TransportablePublicKey[] tpkKeys) {
			bool bCAST5 = true;
			bool bAES256 = true;
			bool bAES192 = true;
			bool bAES128 = true;
			
			for (int i=0; i< tpkKeys.Length; i++) {
				TransportablePublicKey tpkKey = tpkKeys[i];
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
								for (int j=0; j<saThisKey.Length; j++) {
									if (saThisKey[j] == SymAlgorithms.AES128)
										bTmpAES128 = true;
									else if (saThisKey[j] == SymAlgorithms.AES192)
										bTmpAES192 = true;
									else if (saThisKey[j] == SymAlgorithms.AES256)
										bTmpAES256 = true;
									else if (saThisKey[j] == SymAlgorithms.CAST5)
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
		
		
		private ESKSequence CreateESKSequence(TransportablePublicKey[] tpkKeys, AsymActions aaAction, SymAlgorithms saAlgo, byte[] bSymKey) {
			ESKSequence esksReturn = new ESKSequence();
			
			for (int i=0; i<tpkKeys.Length; i++) {
				TransportablePublicKey tpkKey = tpkKeys[i];
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
		
		private byte[] EncryptMessage(Message mToBeEncrypted, ulong[] lTargetKeyIDs) {
			CompressedMessage cmMessage = new CompressedMessage();
			cmMessage.Compress(mToBeEncrypted);
			
			TransportablePublicKey[] tpkSelectedKeys = new TransportablePublicKey[lTargetKeyIDs.Length];
			for (int i=0; i<lTargetKeyIDs.Length; i++)
				tpkSelectedKeys[i] = pkrKeyRing.Find(lTargetKeyIDs[i], true);
			
			SymAlgorithms saAlgo = GetSymAlgorithmPreferences(tpkSelectedKeys);
			
			SymmetricallyEncryptedDataPacket sedpEncrypted = new SymmetricallyEncryptedDataPacket();
			SymmetricAlgorithm saEncrypt = CipherHelper.CreateSymAlgorithm(saAlgo);
			saEncrypt.Mode = CipherMode.OpenPGP_CFB;
			saEncrypt.GenerateKey();
			byte[] bKey = saEncrypt.Key;
			
			ESKSequence esksKeys = new ESKSequence();
			esksKeys = CreateESKSequence(tpkSelectedKeys, AsymActions.Encrypt, saAlgo, bKey);
			
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
			
			return bReturn;
			
		}
		
		private SignedMessage SignMessage(LiteralMessage lmToBeSigned, ulong lSignatureKeyID, string strPassphrase) {
			TransportableSecretKey tskKey = skrKeyRing.Find(lSignatureKeyID);
			SignedMessage smMessage = new SignedMessage();
			smMessage.MessageSigned = lmToBeSigned;
			SignaturePacket spPacket = new SignaturePacket();
			spPacket.Version = SignaturePacketVersionNumbers.v3;
			SecretKeyPacket skpKey = tskKey.FindKey(AsymActions.Sign);
			spPacket.KeyID = skpKey.PublicKey.KeyID;
			spPacket.HashAlgorithm = HashAlgorithms.SHA1;
			spPacket.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
			spPacket.TimeCreated = DateTime.Now;
			spPacket.SignatureType = SignatureTypes.TextSignature;
			spPacket.Sign(lmToBeSigned.Binary, skpKey, strPassphrase);
			smMessage.Signature = spPacket;
			
			return smMessage;
		}
		
		private string DecryptAndVerifyData(byte[] bData, string strPassphrase) {
			// let us see what kind of message this is
			
			bool bSymEncrypted = false;
			bool bAsymEncrypted = false;
			bool bSigned = false;
			
			SharpPrivacyLib.OpenPGP.Messages.Message mContent = null;
			EncryptedMessage emMessage = new EncryptedMessage();
			Packet[] pPackets = Packet.ParsePackets(bData);
			
			XmlDocument xmlDoc = new XmlDocument();
			XmlElement xmlMessage = xmlDoc.CreateElement("OpenPGPMessage");
			
			try {
				emMessage.ParseMessage(pPackets);
				
				if (emMessage.SymmetricallyEncrypted) {
					mContent = emMessage.Decrypt(strPassphrase);
					
					bSymEncrypted = true;
				} else {
					ulong lKeyID = emMessage.GetFittingKeyID(skrKeyRing);
					
					mContent = emMessage.Decrypt(skrKeyRing, strPassphrase);
					bAsymEncrypted = true;
				}
			} catch (ArgumentException) {
				//obviously it wasn't an encrypted message. perhaps the
				//message has only been signed, but not encrypted!
				try {
					SignedMessage smMessage = new SignedMessage();
					smMessage.ParseMessage(pPackets);
					mContent = smMessage;
				} catch (Exception e) {
					throw new Exception("Not a valid OpenPGP Message: " + e.Message);
				}
			}
			
			while ((!(mContent is LiteralMessage)) && (!(mContent is SignedMessage))) {
				if (mContent is CompressedMessage) {
					mContent = ((CompressedMessage)mContent).Uncompress();
				} else {
					throw new Exception("Not a valid OpenPGP Message!");
				}
			}
			
			LiteralMessage lmContent = new LiteralMessage();
			
			if (mContent is SignedMessage) {
				bSigned = true;
				SignedMessage smContent = (SignedMessage)mContent;
				lmContent = smContent.MessageSigned;
				
				xmlMessage.SetAttribute("signaturestatus", smContent.Verify(pkrKeyRing).ToString());
				xmlMessage.SetAttribute("signingkey", "0x" + smContent.Signature.KeyID.ToString("x"));
				xmlMessage.SetAttribute("signingdate", smContent.Signature.TimeCreated.Ticks.ToString());
				
				mContent = lmContent;
				
			}
			
			xmlMessage.SetAttribute("symmetricallyencrypted", bSymEncrypted.ToString());
			xmlMessage.SetAttribute("asymmetricallyencrypted", bAsymEncrypted.ToString());
			xmlMessage.SetAttribute("signed", bSigned.ToString());
			
			XmlElement xmlLiteral = xmlDoc.CreateElement("LiteralMessage");
			if (mContent is LiteralMessage) {
				lmContent = (LiteralMessage)mContent;
				
				xmlLiteral.SetAttribute("dataformat", lmContent.DataFormat.ToString());
				xmlLiteral.SetAttribute("timecreated", lmContent.TimeCreated.Ticks.ToString());
				xmlLiteral.SetAttribute("filename", lmContent.Filename);
				
			} else {
				throw new Exception("Error decrypting the message!");
			}
			
			if (lmContent.DataFormat == DataFormatTypes.Binary) {
				xmlLiteral.InnerText = Convert.ToBase64String(lmContent.Binary);
			} else {
				xmlLiteral.InnerText = lmContent.Text;
			}
			
			xmlMessage.AppendChild(xmlLiteral);
			
			return xmlMessage.OuterXml;
			
			
		}
		
	}
}

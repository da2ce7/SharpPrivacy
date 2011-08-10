//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SignatureSubPacket.cs: 
// 	Class for handling signature sub packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 04.02.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Collections;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// This class represents an RFC2440 (OpenPGP) signature
	/// subpacket. These are only usefull for v4 signature packets.
	/// The class provides means for creating or modifying
	/// signature subpackets.
	/// </summary>
	/// <remarks>No remarks.</remarks>
	public class SignatureSubPacket : object {
		
		private SignatureSubPacketTypes sptType;
		private byte[] bHeader;
		private byte[] bBody;
		private long lLength;

		private DateTime dtTimeCreated;
		private ulong lKeyID;
		private BigInteger revocationkeyID;
		private DateTime dtKeyExpirationTime;
		private SymAlgorithms[] saPreferedSymAlgos;
		private HashAlgorithms[] haPreferedHashAlgorithms;
		private CompressionAlgorithms[] caPreferedCompressionAlgorithms;
		private DateTime dtSignatureExpirationTime;
		private bool bExportableSignature;
		private bool bRevocable;
		private bool bPrimaryUserID;
		private int bSensible = 0;
		private byte bTrustLevel;
		private byte bTrustAmount;
		private string strPreferedKeyServer;
		private string strReasonForRevocation;
		private byte bReasonForRevocationCode;
		private string strNotationName;
		private string strNotationValue;
		private HashAlgorithms fingerprintHash;
		private KeyFlagTypes[] kftKeyFlags;
		private KeyserverPreferencesTypes[] kptKeyserverPreferences;
		
		public int Sensible {
			get {
				return bSensible;
			}
			set {
				bSensible  = value;
			}
		}

		public HashAlgorithms FingerprintHash {
			get {
				return fingerprintHash;
			}
			set {
				fingerprintHash  = value;
			}
		}

		public string NotationValue {
			get {
				return strNotationValue;
			}
			set {
				strNotationValue  = value;
			}
		}
		
		public string NotationName {
			get {
				return strNotationName;
			}
			set {
				strNotationName  = value;
			}
		}
		
		public byte ReasonForRevocationCode {
			get {
				return bReasonForRevocationCode;
			}
			set {
				bReasonForRevocationCode  = value;
			}
		}
		
		public string ReasonForRevocation {
			get {
				return strReasonForRevocation;
			}
			set {
				strReasonForRevocation  = value;
			}
		}

		public BigInteger RevocationKeyID {
			get {
				return revocationkeyID;
			}
			set {
				revocationkeyID  = value;
			}
		}
		
		public SignatureSubPacketTypes Type {
			get {
				return sptType;
			}
			set {
				sptType = value;
			}
		}
		
		public long Length {
			get {
				return bHeader.Length + bBody.Length;
			}
		}
		
		public byte[] Header {
			get {
				return bHeader;
			}
			set {
				bHeader = value;
			}
		}
		
		public byte[] Body {
			get {
				return bBody;
			}
			set {
				bBody = value;
			}
		}
		
		/*****************************************************
		 * Here start of key types. Only ONE of the following
		 * properties is used per Signature Subpacket
		 *****************************************************/
		public byte TrustLevel {
			get {
				return bTrustLevel;
			}
			set {
				bTrustLevel = value;
			}
		}
		
		public KeyserverPreferencesTypes[] KeyserverPreferences {
			get {
				return this.kptKeyserverPreferences;
			}
			set {
				kptKeyserverPreferences = value;
			}
		}
		
		public KeyFlagTypes[] KeyFlags {
			get {
				return kftKeyFlags;
			}
			set {
				kftKeyFlags = value;
			}
		}
		
		public string PreferedKeyServer {
			get {
				return strPreferedKeyServer;
			}
			set {
				strPreferedKeyServer = value;
			}
		}
		
		public byte TrustAmount {
			get {
				return bTrustAmount;
			}
			set {
				bTrustAmount = value;
			}
		}
		
		public DateTime TimeCreated {
			get {
				return dtTimeCreated;
			}
			set {
				Type = SignatureSubPacketTypes.SignatureCreationTime;
				dtTimeCreated = value;
			}
		}
		
		public ulong KeyID {
			get {
				return lKeyID;
			}
			set {
				Type = SignatureSubPacketTypes.IssuerKeyID;
				lKeyID = value;
			}
		}
		
		public DateTime KeyExpirationTime {
			get {
				return dtKeyExpirationTime;
			}
			set {
				Type = SignatureSubPacketTypes.KeyExpirationTime;
				dtKeyExpirationTime = value;
			}
		}
		
		public DateTime SignatureExpirationTime {
			get {
				return dtSignatureExpirationTime;
			}
			set {
				Type = SignatureSubPacketTypes.SignatureExpirationTime;
				dtSignatureExpirationTime = value;
			}
		}

		public SymAlgorithms[] PreferedSymAlgos {
			get {
				return saPreferedSymAlgos;
			}
			set {
				Type = SignatureSubPacketTypes.PreferedSymmetricAlgorithms;
				saPreferedSymAlgos = value;
			}
		}
		
		public HashAlgorithms[] PreferedHashAlgos {
			get {
				return haPreferedHashAlgorithms;
			}
			set {
				Type = SignatureSubPacketTypes.PreferedHashAlgorithms;
				haPreferedHashAlgorithms = value;
			}
		}

		public CompressionAlgorithms[] PreferedCompressionAlgos {
			get {
				return caPreferedCompressionAlgorithms;
			}
			set {
				Type = SignatureSubPacketTypes.PreferedCompressionAlgorithms;
				caPreferedCompressionAlgorithms = value;
			}
		}
		
		public bool ExportableSignature {
			get {
				return bExportableSignature;
			}
			set {
				Type = SignatureSubPacketTypes.ExportableSignature;
				bExportableSignature = value;
			}
		}

		public bool Revocable {
			get {
				return bRevocable;
			}
			set {
				Type = SignatureSubPacketTypes.Revocable;
				bRevocable = value;
			}
		}

		public bool PrimaryUserID {
			get {
				return bPrimaryUserID;
			}
			set {
				Type = SignatureSubPacketTypes.PrimaryUserID;
				bPrimaryUserID = value;
			}
		}

		/// <summary>
		/// Returns a string representation of the subpacket. This is
		/// a human readable formated representation that has nothing
		/// to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the subpacket.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "";
			
			strReturn += "Signature Subpacket:\r\n";
			strReturn += "Type: " + sptType.ToString() + "\r\n";
			
			switch (sptType) {
				case SignatureSubPacketTypes.SignatureCreationTime:
					strReturn += "TimeCreated: " + dtTimeCreated.ToLocalTime() + "\r\n";
					break;
				case SignatureSubPacketTypes.IssuerKeyID:
					strReturn += "Issuer KeyID: " + lKeyID.ToString() + "\r\n";
					break;
				case SignatureSubPacketTypes.KeyServerPreferences:
					for (int i=0; i<kptKeyserverPreferences.Length; i++) {
						strReturn += "Keyserver Preferences: " + kptKeyserverPreferences[i].ToString() + "\r\n";
					}
					break;
				case SignatureSubPacketTypes.TrustSignature:
					strReturn += "Trust Level: " + bTrustLevel + "\r\n";
					strReturn += "Trust Amount: " + bTrustAmount + "\r\n";
					break;
				case SignatureSubPacketTypes.KeyExpirationTime:
					strReturn += "Key Expiration Time: " + dtKeyExpirationTime.ToLocalTime() + "\r\n";
					break;
				case SignatureSubPacketTypes.KeyFlags:
					for (int i=0; i<kftKeyFlags.Length; i++) {
						strReturn += "Key Flags: ";
						if (((byte)KeyFlagTypes.CertifyKey & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "CertifyKey, ";
						}
						if (((byte)KeyFlagTypes.CommunicationEncryptionKey & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "CommunicationEncryptionKey, ";
						}
						if (((byte)KeyFlagTypes.DataSigningKey & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "DataSigningKey, ";
						}
						if (((byte)KeyFlagTypes.SplitKey & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "SplitKey, ";
						}
						if (((byte)KeyFlagTypes.StorageEncryptionKey & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "StorageEncryptionKey, ";
						}
						if (((byte)KeyFlagTypes.UsedByMorePersons & (byte)kftKeyFlags[i]) > 0) {
							strReturn += "UsedByMorePersons, ";
						}
						strReturn = strReturn.Substring(0, strReturn.Length - 2) + "\r\n";
					}
					break;
				case SignatureSubPacketTypes.SignatureExpirationTime:
					strReturn += "Signature Expiration Time: " + dtSignatureExpirationTime.ToLocalTime() + "\r\n";
					break;
				case SignatureSubPacketTypes.PreferedSymmetricAlgorithms:
					strReturn += "Prefered Symmetrical Algorithms: ";
					for (int i=0; i<saPreferedSymAlgos.Length; i++)
						strReturn += saPreferedSymAlgos[i].ToString() + ", ";
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.PreferedHashAlgorithms:
					strReturn += "Prefered Hash Algorithms: ";
					for (int i=0; i<haPreferedHashAlgorithms.Length; i++)
						strReturn += haPreferedHashAlgorithms[i].ToString() + ", ";
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.PreferedCompressionAlgorithms:
					strReturn += "Prefered Compression Algorithms: ";
					for (int i=0; i<caPreferedCompressionAlgorithms.Length; i++)
						strReturn += caPreferedCompressionAlgorithms[i].ToString() + ", ";
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.ExportableSignature:
					strReturn += "Exportable Signature: " + bExportableSignature.ToString();
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.PreferedKeyServer:
					strReturn += "Prefered Keyserver: " + strPreferedKeyServer + "\r\n";
					break;
				case SignatureSubPacketTypes.Revocable:
					strReturn += "Revocable Signature: " + bRevocable.ToString();
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.PrimaryUserID:
					strReturn += "Primary UserID: " + bPrimaryUserID.ToString();
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.RevocationKey:
					strReturn += "Revoker Key Fingerprint: " + RevocationKeyID.ToString();
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.ReasonForRevocation:
					strReturn += "Reason For Revocation: " + ReasonForRevocationCode + "  " + ReasonForRevocation;
					strReturn += "\r\n";
					break;
				case SignatureSubPacketTypes.NotationData:
					strReturn += "Notation: " + NotationName + "   Value:" + NotationValue;
					strReturn += "\r\n";
					break;
				
				default: // Everything else
					strReturn += "This subpacket is not yet implemented!\r\n";
					break;
			}
			
			return strReturn;
			
		}
		
		public SignatureSubPacket[] ParsePackets(byte[] bBinaryData) {
			ArrayList alPackets	= new ArrayList(100);
			byte[] bTmpData = new byte[bBinaryData.Length];
			Array.Copy(bBinaryData, bTmpData, bBinaryData.Length);
			
			long iCurrentIndex = 0;
			
			while (iCurrentIndex < bBinaryData.Length) {
				SignatureSubPacket pTmpPacket = new SignatureSubPacket();
				SignatureSubPacket pCurrentPacket = pTmpPacket.ParsePacket(bTmpData);
				
				iCurrentIndex += pCurrentPacket.Length;
				alPackets.Add(pCurrentPacket);
				
				bTmpData = new byte[bTmpData.Length - pCurrentPacket.Length];
				Array.Copy(bBinaryData, (int)iCurrentIndex, bTmpData, 0, bBinaryData.Length - (int)iCurrentIndex);
			}
			
			SignatureSubPacket[] pReturnPackets = new SignatureSubPacket[alPackets.Count];
			IEnumerator iePacketEnum = alPackets.GetEnumerator();
			int iCount = 0;
			while (iePacketEnum.MoveNext()) {
				pReturnPackets[iCount++] = (SignatureSubPacket)iePacketEnum.Current;
			}

			return pReturnPackets;
			
		}

		/// <summary>
		/// Parses the signature subpacket given as byte array into 
		/// the current class and returns this with the populated 
		/// parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the signature subpacket.</param>
		/// <returns>Returns an SignatureSubPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public SignatureSubPacket ParsePacket(byte[] bData) {
			lLength = bData[0];
			if (lLength < 192) {
				bHeader = new byte[2];
				bBody = new byte[lLength-1];
				Array.Copy(bData, 0, bHeader, 0, 2);
				Array.Copy(bData, 2, bBody, 0, (int)lLength-1);
				sptType = (SignatureSubPacketTypes)bData[1];
			} else if ((lLength > 191) && (lLength < 255)) {
				lLength = ((bData[0] - 192) << 8) + bData[1] + 192;
				bHeader = new byte[3];
				bBody = new byte[lLength-1];
				Array.Copy(bData, 0, bHeader, 0, 3);
				Array.Copy(bData, 3, bBody, 0, (int)lLength-1);
				sptType = (SignatureSubPacketTypes)bData[2];
			} else { //lLength == 255
				lLength = (bData[1] << 24) ^ (bData[2] << 16) ^
						  (bData[3] << 8) ^ bData[4];
				bHeader = new byte[6];
				bBody = new byte[lLength-1];
				Array.Copy(bData, 0, bHeader, 0, 6);
				Array.Copy(bData, 6, bBody, 0, (int)lLength-1);
				sptType = (SignatureSubPacketTypes)bData[5];
			}
			
			// TODO: Add Error Handling!!!
			long iTime = 0;
			switch (sptType) {
				case SignatureSubPacketTypes.SignatureCreationTime:
					iTime = bBody[0] << 24;
					iTime ^= bBody[1] << 16;
					iTime ^= bBody[2] << 8;
					iTime ^= bBody[3];
					dtTimeCreated = new DateTime(iTime*10000000 + new DateTime(1970, 1, 1).Ticks);
					break;
				case SignatureSubPacketTypes.IssuerKeyID:
					lKeyID = (ulong)bBody[0] << 56;
					lKeyID ^= (ulong)bBody[1] << 48;
					lKeyID ^= (ulong)bBody[2] << 40;
					lKeyID ^= (ulong)bBody[3] << 32;
					lKeyID ^= (ulong)bBody[4] << 24;
					lKeyID ^= (ulong)bBody[5] << 16;
					lKeyID ^= (ulong)bBody[6] << 8;
					lKeyID ^= (ulong)bBody[7];
					break;
				case SignatureSubPacketTypes.KeyServerPreferences:
					kptKeyserverPreferences = new KeyserverPreferencesTypes[bBody.Length];
					for (int i=0; i<bBody.Length; i++)
						this.kptKeyserverPreferences[i] = (KeyserverPreferencesTypes)bBody[i];
					break;
				case SignatureSubPacketTypes.PreferedKeyServer:
					char[] cKeyserver = new char[bBody.Length];
					Array.Copy(bBody, cKeyserver, bBody.Length);
					strPreferedKeyServer = cKeyserver.ToString();
					break;
				case SignatureSubPacketTypes.TrustSignature:
					bTrustLevel = bBody[0];
					bTrustAmount = bBody[1];
					break;
				case SignatureSubPacketTypes.KeyFlags:
					kftKeyFlags = new KeyFlagTypes[bBody.Length];
					for (int i=0; i<bBody.Length; i++) 
						kftKeyFlags[i] = (KeyFlagTypes)bBody[i];
					break;
				case SignatureSubPacketTypes.KeyExpirationTime:
					iTime = bBody[0] << 24;
					iTime ^= bBody[1] << 16;
					iTime ^= bBody[2] << 8;
					iTime ^= bBody[3];
					dtKeyExpirationTime = new DateTime(iTime*10000000 + new DateTime(1970, 1, 1).Ticks);
					break;	
				case SignatureSubPacketTypes.SignatureExpirationTime:
					iTime = bBody[0] << 24;
					iTime ^= bBody[1] << 16;
					iTime ^= bBody[2] << 8;
					iTime ^= bBody[3];
					dtSignatureExpirationTime = new DateTime(iTime*10000000 + new DateTime(1970, 1, 1).Ticks);
					break;	
				case SignatureSubPacketTypes.PreferedSymmetricAlgorithms:
					saPreferedSymAlgos = new SymAlgorithms[bBody.Length];
					for (int i=0; i<bBody.Length; i++)
						saPreferedSymAlgos[i] = (SymAlgorithms)bBody[i];
					break;
				case SignatureSubPacketTypes.PreferedHashAlgorithms:
					haPreferedHashAlgorithms = new HashAlgorithms[bBody.Length];
					for (int i=0; i<bBody.Length; i++)
						haPreferedHashAlgorithms[i] = (HashAlgorithms)bBody[i];
					break;
				case SignatureSubPacketTypes.PreferedCompressionAlgorithms:
					caPreferedCompressionAlgorithms = new CompressionAlgorithms[bBody.Length];
					for (int i=0; i<bBody.Length; i++)
						caPreferedCompressionAlgorithms[i] = (CompressionAlgorithms)bBody[i];
					break;
				case SignatureSubPacketTypes.ExportableSignature:
					bExportableSignature = (bBody[0] == 1);
					break;
				case SignatureSubPacketTypes.Revocable:
					bRevocable = (bBody[0] == 1);
					break;
				case SignatureSubPacketTypes.PrimaryUserID:
					bPrimaryUserID = (bBody[0] == 1);
					break;
				case SignatureSubPacketTypes.RevocationKey:
					this.Sensible = (bBody[1] >> 3) & 0x01;
					this.FingerprintHash = (HashAlgorithms)bBody[1];
					byte[] fingerprint = new byte[bBody.Length-2];
					for(int i = 2; i < bBody.Length; i++)
						fingerprint[i-2] = bBody[i];

					this.RevocationKeyID = new BigInteger(fingerprint);
					break;
				case SignatureSubPacketTypes.ReasonForRevocation:
					byte[] reason = new byte[bBody.Length-1];
					for(int i = 1; i < bBody.Length; i++)
						reason[i-1] = bBody[i];

					this.ReasonForRevocationCode = bBody[0];
					char [] reasArray = new char[reason.Length];
					Array.Copy(reason,reasArray,reason.Length);
					this.ReasonForRevocation = new string(reasArray);
					break;
				case SignatureSubPacketTypes.NotationData:
					int nameLength = bBody[4] << 8;
					nameLength ^= bBody[5];
					int valueLength = bBody[6] << 8;
					valueLength ^= bBody[7];
					byte[] name = new byte[nameLength];
					byte[] val = new byte[valueLength];
					for(int i = 8; i < nameLength + 8; i++)
						name[i-8] = bBody[i];

					for(int i = nameLength + 8; i < valueLength + nameLength + 8; i++)
						val[i-nameLength-8] = bBody[i];

					char [] notnamArray = new char[nameLength];
					Array.Copy(name,notnamArray,name.Length);
					this.NotationName = new string(notnamArray);
					char [] notvalArray = new char[valueLength];
					Array.Copy(val,notvalArray,val.Length);
					this.NotationValue = new string(notvalArray);
					break;					
						
					
			}
			
			return this;
		}
		
		public byte[] Generate() {
			byte[] bBody = PrepareHash();
			byte[] bData = new byte[0];
			
			int iCounter = 0;
			if (bBody.Length+1 < 192) {
				bData = new byte[bBody.Length + 2];
				bData[iCounter++] = (byte)(bBody.Length+1);
			} else if (bBody.Length+1 < 8384) {
				bData = new byte[bBody.Length + 3];
				bData[iCounter++] = (byte)((bBody.Length+1 - 192) / 256 + 192);
				bData[iCounter++] = (byte)((bBody.Length+1 - 192) % 256);
			} else {
				bData = new byte[bBody.Length + 6];
				bData[iCounter++] = 255;
				bData[iCounter++] = (byte)((bBody.Length+1 >> 24) & 0xFF);
				bData[iCounter++] = (byte)((bBody.Length+1 >> 16) & 0xFF);
				bData[iCounter++] = (byte)((bBody.Length+1 >> 8) & 0xFF);
				bData[iCounter++] = (byte)(bBody.Length+1 & 0xFF);
			}
			bData[iCounter++] = (byte)this.Type;
			Array.Copy(bBody, 0, bData, iCounter, bBody.Length);
			
			return bData;
		}
		
		protected byte[] PrepareHash() {
			byte[] bReturn = new byte[0];
			long iTime;
			
			switch (sptType) {
				case SignatureSubPacketTypes.SignatureCreationTime:
					bReturn = new byte[4];
					iTime = (dtTimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
					bReturn[0] = (byte)((iTime >> 24) & 0xFF);
					bReturn[1] = (byte)((iTime >> 16) & 0xFF);
					bReturn[2] = (byte)((iTime >> 8) & 0xFF);
					bReturn[3] = (byte)(iTime & 0xFF);
					break;
				case SignatureSubPacketTypes.IssuerKeyID:
					bReturn = new byte[8];
					bReturn[0] = (byte)((lKeyID >> 56) & 0xFF);
					bReturn[1] = (byte)((lKeyID >> 48) & 0xFF);
					bReturn[2] = (byte)((lKeyID >> 40) & 0xFF);
					bReturn[3] = (byte)((lKeyID >> 32) & 0xFF);
					bReturn[4] = (byte)((lKeyID >> 24) & 0xFF);
					bReturn[5] = (byte)((lKeyID >> 16) & 0xFF);
					bReturn[6] = (byte)((lKeyID >> 8) & 0xFF);
					bReturn[7] = (byte)(lKeyID & 0xFF);
					break;
				case SignatureSubPacketTypes.KeyServerPreferences:
					bReturn = new byte[KeyserverPreferences.Length];
					for (int i=0; i<KeyserverPreferences.Length; i++)
						bReturn[i] = (byte)this.KeyserverPreferences[i];
					break;
				case SignatureSubPacketTypes.PreferedKeyServer:
					bReturn = new byte[strPreferedKeyServer.Length];
					char[] cKeyserver = strPreferedKeyServer.ToCharArray();
					for (int i=0; i<cKeyserver.Length; i++) {
						bReturn[i] = (byte)cKeyserver[i];
					}
					break;
				case SignatureSubPacketTypes.KeyFlags:
					bReturn = new byte[kftKeyFlags.Length];
					for (int i=0; i<kftKeyFlags.Length; i++)
						bReturn[i] = (byte)kftKeyFlags[i];
					break;
				case SignatureSubPacketTypes.TrustSignature:
					bReturn = new byte[2];
					bReturn[0] = bTrustLevel;
					bReturn[1] = bTrustAmount;
					break;
				case SignatureSubPacketTypes.KeyExpirationTime:
					bReturn = new byte[4];
					iTime = (this.dtKeyExpirationTime.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
					bReturn[0] = (byte)((iTime >> 24) & 0xFF);
					bReturn[1] = (byte)((iTime >> 16) & 0xFF);
					bReturn[2] = (byte)((iTime >> 8) & 0xFF);
					bReturn[3] = (byte)(iTime & 0xFF);
					break;
				case SignatureSubPacketTypes.SignatureExpirationTime:
					bReturn = new byte[4];
					iTime = (dtSignatureExpirationTime.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
					bReturn[0] = (byte)((iTime >> 24) & 0xFF);
					bReturn[1] = (byte)((iTime >> 16) & 0xFF);
					bReturn[2] = (byte)((iTime >> 8) & 0xFF);
					bReturn[3] = (byte)(iTime & 0xFF);
					break;
				case SignatureSubPacketTypes.PreferedSymmetricAlgorithms:
					bReturn = new byte[saPreferedSymAlgos.Length];
					for (int i=0; i<saPreferedSymAlgos.Length; i++)
						bReturn[i] = (byte)saPreferedSymAlgos[i];
					break;
				case SignatureSubPacketTypes.PreferedHashAlgorithms:
					bReturn = new byte[haPreferedHashAlgorithms.Length];
					for (int i=0; i<haPreferedHashAlgorithms.Length; i++)
						bReturn[i] = (byte)haPreferedHashAlgorithms[i];
					break;
				case SignatureSubPacketTypes.PreferedCompressionAlgorithms:
					bReturn = new byte[caPreferedCompressionAlgorithms.Length];
					for (int i=0; i<caPreferedCompressionAlgorithms.Length; i++)
						bReturn[i] = (byte)caPreferedCompressionAlgorithms[i];
					break;
				case SignatureSubPacketTypes.ExportableSignature:
					bReturn = new byte[1];
					bReturn[0] = 0;
					if (bExportableSignature)
						bReturn[0] = 1;	
					break;
				case SignatureSubPacketTypes.Revocable:
					bReturn = new byte[1];
					bReturn[0] = 0;
					if (bRevocable)
						bReturn[0] = 1;	
					break;
				case SignatureSubPacketTypes.PrimaryUserID:
					bReturn = new byte[1];
					bReturn[0] = 0;
					if (bPrimaryUserID)
						bReturn[0] = 1;	
					break;
				case SignatureSubPacketTypes.RevocationKey:
					byte[] fingerprint = this.RevocationKeyID.getBytes();
					bReturn = new byte[2 + fingerprint.Length];
					Array.Copy(fingerprint,0,bReturn,2,fingerprint.Length);
					bReturn[0] = (byte)(((1 & 0x80) | (this.Sensible << 3)) & 0xFF);
					bReturn[1] = (byte)this.FingerprintHash;
					break;
				case SignatureSubPacketTypes.ReasonForRevocation:
					char[] reason = this.ReasonForRevocation.ToCharArray();
					bReturn = new byte[reason.Length+1];
					for (int i=0; i<reason.Length; i++) 
						bReturn[i+1] = (byte)reason[i];

					bReturn[0] = this.ReasonForRevocationCode;
					break;
				case SignatureSubPacketTypes.NotationData:
					char[] name = this.NotationName.ToCharArray();
					char[] nValue = this.NotationValue.ToCharArray();
					bReturn = new byte[name.Length+nValue.Length+8];
					for (int i=0; i<name.Length; i++) 
						bReturn[i+8] = (byte)name[i];

					for (int i=0; i<nValue.Length; i++) 
						bReturn[i+8+name.Length] = (byte)nValue[i];

					bReturn[0] = (byte) 1 & 0x80;
					bReturn[4] = (byte)((name.Length >> 8) & 0xFF);
					bReturn[5] = (byte)(name.Length & 0xFF);
					bReturn[6] = (byte)((nValue.Length >> 8) & 0xFF);
					bReturn[7] = (byte)(nValue.Length & 0xFF);
					break;
			}
			
			return bReturn;
		}
		

	}
}

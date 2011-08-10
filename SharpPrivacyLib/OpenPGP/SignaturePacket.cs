//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SignaturePacket.cs: 
// 	Class for handling signature packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 16.01.2003: Created this file.
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
	/// This class represents an OpenPGP signature packet.
	/// It helps to sign and verify data and make up RFC conform
	/// signature packets.
	/// </summary>
	/// <remarks>No remarks.</remarks>
	public class SignaturePacket : Packet {
		
		//v3 and v4 tags
		private SignaturePacketVersionNumbers vnVersion = SignaturePacketVersionNumbers.v4;
		private SignatureTypes stSignatureType;
		private DateTime dtTimeCreated;
		private ulong lKeyID;
		private AsymAlgorithms aaSignatureAlgorithm;
		private HashAlgorithms haHashAlgorithm;
		private ushort sSignedHash16Bit;
		private BigInteger[] biSignature;
		private SignatureSubPacket[] sspHashedSubPackets;
		private SignatureSubPacket[] sspUnhashedSubPackets;
		private SignatureStatusTypes ssSignatureStatus;
		private byte[] bHashedPart;
		private byte[] bSignatureData;
		
		/// <summary>
		/// Creates a new SignaturePacket with the parameters
		/// in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		/// <remarks>No remarks</remarks>
		public SignaturePacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			bSignatureData = new byte[0];
			ssSignatureStatus = SignatureStatusTypes.Not_Verified;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new signature packet. Format defaults
		/// to new packet format.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public SignaturePacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.Signature;
			dtTimeCreated = DateTime.Now;
			HashedSubPackets = new SignatureSubPacket[0];
			UnhashedSubPackets = new SignatureSubPacket[0];
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// Readonly - Returns the status of the signature. This can be
		/// either valid, invalid, not yet verified or signing key not
		/// available.
		/// </summary>
		/// <remarks>This property has the value "not yet verified" just
		/// as long, as the method Verify() has not been called.
		/// </remarks>
		/// <value>The status of the signature. This can be
		/// either valid, invalid, not yet verified or signing key not
		/// available.</value>
		public SignatureStatusTypes SignatureStatus {
			get {
				return ssSignatureStatus;
			}
			set {
				this.ssSignatureStatus = value;
			}		}
		
		/// <summary>
		/// Gets or sets an array of signature subpackets. The content of
		/// this array will be hashed in the final signature.
		/// </summary>
		/// <remarks>
		/// <para>Signature subpackets are only available for v4 
		/// signatures.</para> 
		/// <para>Take care to put all modification-sensitiv data into 
		/// hashed subpackets, as unhashed subpackets can be modified 
		/// without invalidating the signature.</para>
		/// </remarks>
		/// <value>An array of signature subpackets.</value>
		public SignatureSubPacket[] HashedSubPackets {
			get {
				return sspHashedSubPackets;
			}
			set {
				this.bIsUpdated = true;
				sspHashedSubPackets = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an array of signature subpackets. The content of
		/// this array will NOT be hashed in the final signature.
		/// </summary>
		/// <remarks>
		/// <para>Signature subpackets are only available for v4 
		/// signatures.</para> 
		/// <para>Take care to put all modification-sensitiv data into 
		/// hashed subpackets, as unhashed subpackets can be modified 
		/// without invalidating the signature.</para>
		/// </remarks>
		/// <value>An array of signature subpackets.</value>
		public SignatureSubPacket[] UnhashedSubPackets {
			get {
				return sspUnhashedSubPackets;
			}
			set {
				this.bIsUpdated = true;
				sspUnhashedSubPackets = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an array of biginteger composing the actual
		/// signature. 
		/// </summary>
		/// <remarks>The order of the signature components is according
		/// to the OpenPGP RFC.</remarks>
		/// <value>An array of biginteger composing the actual
		/// signature. </value>
		public BigInteger[] Signature {
			get {
				return biSignature;
			}
			set {
				this.bIsUpdated = true;
				biSignature = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the version of the signaturepacket.
		/// </summary>
		/// <remarks>Version can be either v3 or v4. If you use v3 
		/// signatures, you cannot use hashed or unhashed subpackets.
		/// On the other hand if you are using v4 signatures, the
		/// properties KeyID and TimeCreated are meaningless.
		/// </remarks>
		/// <value>The version of the signaturepacket.</value>
		public SignaturePacketVersionNumbers Version {
			get {
				return vnVersion;
			}
			set {
				this.bIsUpdated = true;
				vnVersion = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the type of the signature. 
		/// </summary>
		/// <remarks>Look at the enum
		/// <see cref="SignatureTypes">SignatureTypes</see> for
		/// a list of what this can be, and what the meanings of
		/// the singular types are.</remarks>
		/// <value>The type of the signature.</value>
		public SignatureTypes SignatureType {
			get {
				return stSignatureType;
			}
			set {
				this.bIsUpdated = true;
				stSignatureType = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the date and time when the signature was created.
		/// </summary>
		/// <remarks>This property can be get for both v3 and v4 signature
		/// packets, but it can only be set for v3 signature packets. For
		/// a v4 signature, you have to manually add an issuerkeyid 
		/// subpacket!</remarks>
		/// <value>The date and time when the signature was 
		/// created.</value>
		public DateTime TimeCreated {
			get {
				if (this.vnVersion <= SignaturePacketVersionNumbers.v3) {
					return dtTimeCreated;
				} else {
					return  FindSignatureCreationTime();
				}
			}
			set {
				this.bIsUpdated = true;
				dtTimeCreated = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the key id of the key that created the signature.
		/// </summary>
		/// <remarks>This property can be get for both v3 and v4 signature
		/// packets, but it can only be set for v3 signature packets. For
		/// a v4 signature, you have to manually add an issuerkeyid 
		/// subpacket!</remarks>
		/// <value>The key id of the key that created the signature.
		/// </value>
		public ulong KeyID {
			get {
				if (this.vnVersion <= SignaturePacketVersionNumbers.v3) {
					return lKeyID;
				} else {
					ulong ltmpKey = FindIssuerKeyID();
					if (ltmpKey > 0)
						return ltmpKey;
					else
						throw new Exception("This signaturepacket does not include the mandatory issuer key id! Very strange!");
				}
			}
			set {
				this.bIsUpdated = true;
				lKeyID = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the signature algorithm used to sign
		/// the message.
		/// </summary>
		/// <remarks>The signature algorithm of the signature MUST
		/// of course match the algorithm of the key that is used to
		/// sign.</remarks>
		/// <value>The signature algorithm used to sign the 
		/// message.</value>
		public AsymAlgorithms SignatureAlgorithm {
			get {
				return aaSignatureAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				aaSignatureAlgorithm = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the hash algorithm used to calculate a 
		/// message digest over which to signature is formed.
		/// </summary>
		/// <remarks>The hashalgorithm must be chosen out of the key
		/// preferences of the user's key.</remarks>
		/// <value>The hash algorithm used to calculate a 
		/// message digest over which to signature is formed.</value>
		public HashAlgorithms HashAlgorithm {
			get {
				return haHashAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				haHashAlgorithm = value;
			}
		}
		
		/// <summary>
		/// Gets the higher 16 bits of the hash from the signature.
		/// </summary>
		/// <remarks>This is used to quickly check if the signature
		/// is valid or not. If the lower 16 bit are ok, you still have
		/// to check the signature.</remarks>
		/// <value>The higher 16 bits of the hash from the signature.</value>
		public ushort SignedHash16Bit {
			get {
				return sSignedHash16Bit;
			}
		}
		
		/// <summary>
		/// Returns a string representation of the packet. This is
		/// a human readable formated representation that has nothing
		/// to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the packet.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "";
			
			strReturn += "Signature Packet:\r\n";
			strReturn += "Version: " + Version.ToString() + "\r\n";
			strReturn += "Signaturetype: " + SignatureType.ToString() + "\r\n";
			strReturn += "Signaturealgorithm: " + SignatureAlgorithm.ToString() + "\r\n";
			strReturn += "Hashalgorithm: " + HashAlgorithm.ToString() + "\r\n";
			strReturn += "Time Created: " + TimeCreated.ToLocalTime() + "\r\n";
			strReturn += "KeyID: " + KeyID + "\r\n";
			strReturn += "Hashed Subpackets: " + HashedSubPackets.Length + "\r\n";
			
			for (int i=0; i<HashedSubPackets.Length; i++) 
				strReturn += HashedSubPackets[i].ToString() + "\r\n";

			strReturn += "\r\nUnhashed Subpackets: " + UnhashedSubPackets.Length + "\r\n";
			for (int i=0; i<UnhashedSubPackets.Length; i++) 
				strReturn += UnhashedSubPackets[i].ToString() + "\r\n";
			
			strReturn += "Key Material:\r\n";
			
			for (int i=0; i<Signature.Length; i++)
				strReturn += Signature[i].ToString(16) + "\r\n\r\n";
			
			return strReturn + "----\r\n\r\n";
			
		}
		
		/// <summary>
		/// Signes the data given as parameter with the given secret key.
		/// The given password has to fit the given key.
		/// </summary>
		/// <remarks>
		/// <para>The function calculates a message digest over the given signature
		/// data and signes the digest with the given key.</para>
		/// <para>The results of the signature operation are directly stored
		/// in the Signature property of this class.</para>
		/// </remarks>
		/// <param name="bSignedData">The data that is to be signed.</param>
		/// <param name="skpKey">The key that is to sign the data</param>
		/// <param name="strPassphrase">The passphrase that is neccessary to
		/// decrypt the given key.</param>
		public void Sign(byte[] bSignedData, SecretKeyPacket skpKey, string strPassphrase) {
			System.Security.Cryptography.HashAlgorithm haSigner;
			AsymmetricCipher acSigner;
			
			this.SignatureAlgorithm = skpKey.PublicKey.Algorithm;
			
			switch (this.HashAlgorithm) {
				case HashAlgorithms.MD5:
					haSigner = System.Security.Cryptography.MD5.Create();
					break;
				case HashAlgorithms.SHA1:
					haSigner = System.Security.Cryptography.SHA1.Create();
					break;
				default:
					throw(new System.Exception("Currently only MD5 and SHA1 are implemented as hash algorithms!"));
			}
			
			switch (this.SignatureAlgorithm) {
				case AsymAlgorithms.DSA:
					acSigner = new SharpPrivacy.SharpPrivacyLib.Cipher.DSA();
					break;
				case AsymAlgorithms.RSA_Encrypt_Sign:
				case AsymAlgorithms.RSA_Sign_Only:
					acSigner = new SharpPrivacy.SharpPrivacyLib.Cipher.RSA();
					break;
				default:
					throw(new System.Exception("Currently only DSA and RSA are implemented as signature algorithms!"));
			}
			
			byte[] bSignature = new byte[0];
			int iCounter = 0;
			if (this.Version <= SignaturePacketVersionNumbers.v3) {
				bSignature = new byte[5];
				
				bSignature[iCounter++] = (byte)this.SignatureType;
				long lTime = (dtTimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
				bSignature[iCounter++] = (byte)((lTime >> 24) & 0xFF);
				bSignature[iCounter++] = (byte)((lTime >> 16) & 0xFF);
				bSignature[iCounter++] = (byte)((lTime >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)(lTime & 0xFF);
			} else {
				
				// Add Issuer KeyID Subpacket if it's not there.
				try {
					ulong lTestForKeyID = this.KeyID;
				} catch (Exception) {
					SignatureSubPacket sspIssuerKeyID = new SignatureSubPacket();
					sspIssuerKeyID.Type = SignatureSubPacketTypes.IssuerKeyID;
					sspIssuerKeyID.KeyID = this.lKeyID;
					this.AddSubPacket(sspIssuerKeyID, true);
				}
				
				// Add TimeCreated Subpacket if it's not there.
				try {
					this.FindSignatureCreationTime();
				} catch (Exception) {
					SignatureSubPacket sspCreationTime = new SignatureSubPacket();
					sspCreationTime.Type = SignatureSubPacketTypes.SignatureCreationTime;
					sspCreationTime.TimeCreated = DateTime.Now;
					this.AddSubPacket(sspCreationTime, true);
				}
				
				//Hashed Subpackets Length
				int lHashedSubPacketLength = 0;
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					lHashedSubPacketLength += this.HashedSubPackets[i].Generate().Length;
				}
				
				bSignature = new byte[lHashedSubPacketLength + 12];
				bSignature[iCounter++] = 4; // Version
				bSignature[iCounter++] = (byte)this.SignatureType;
				bSignature[iCounter++] = (byte)this.SignatureAlgorithm;
				bSignature[iCounter++] = (byte)this.HashAlgorithm;
				
				//Hashed
				bSignature[iCounter++] = (byte)((lHashedSubPacketLength >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)(lHashedSubPacketLength & 0xFF);
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					byte[] bSubPacket = this.HashedSubPackets[i].Generate();
					Array.Copy(bSubPacket, 0, bSignature, iCounter, bSubPacket.Length);
					iCounter += bSubPacket.Length;
				}
				
				//Final Trailer of 6 bytes
				bSignature[iCounter++] = 0x04;
				bSignature[iCounter++] = 0xFF;
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 24) & 0xFF);
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 16) & 0xFF);
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)((lHashedSubPacketLength+6) & 0xFF);
			}
			
			byte[] bData = new byte[bSignedData.Length + bSignature.Length];
			Array.Copy(bSignedData, bData, bSignedData.Length);
			Array.Copy(bSignature, 0, bData, bSignedData.Length, bSignature.Length);
			
			byte[] bHash = haSigner.ComputeHash(bData);
			BigInteger biHash = new BigInteger(bHash);

			//PKCS1 Encode the hash
			if (this.SignatureAlgorithm != AsymAlgorithms.DSA) {
				
				// We encode the MD in this way:
				//  0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
				// PAD consists of FF bytes.
				byte[] bASN = new byte[0];
				
				switch (this.HashAlgorithm) {
					case HashAlgorithms.MD5:
						bASN = new byte[] {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
						                   0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 
						                   0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
						break;
					case HashAlgorithms.SHA1:
						bASN = new byte[] {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 
						                   0x2b, 0x0E, 0x03, 0x02, 0x1A, 0x05, 
						                   0x00, 0x04, 0x14};
						break;
				}
				
				int iFrameSize = (skpKey.PublicKey.KeyMaterial[0].bitCount() + 7) / 8;
				byte[] bFrame = new byte[iFrameSize];
				int iASNCounter = 0;
				
				bFrame[iASNCounter++] = 0;
				bFrame[iASNCounter++] = 1;
				int iFFLength = iFrameSize - bHash.Length - bASN.Length - 3;
				for (int i=0; i<iFFLength; i++)
					bFrame[iASNCounter++] = 0xFF;
				
				bFrame[iASNCounter++] = 0;
				Array.Copy(bASN, 0, bFrame, iASNCounter, bASN.Length);
				iASNCounter += bASN.Length;
				Array.Copy(bHash, 0, bFrame, iASNCounter, bHash.Length);
				biHash = new BigInteger(bFrame);
			}
			
			sSignedHash16Bit = (ushort)((bHash[0] << 8) + bHash[1]);
			biSignature = acSigner.Sign(biHash, skpKey, strPassphrase);
			this.bIsUpdated = true;
		}
		
		public void AddSubPacket(SignatureSubPacket sspSubPacket, bool bHashed) {
			if (bHashed) {
				SignatureSubPacket[] sspHashed = new SignatureSubPacket[this.HashedSubPackets.Length + 1];
				Array.Copy(this.HashedSubPackets, 0, sspHashed, 0, this.HashedSubPackets.Length);
				sspHashed[sspHashed.Length - 1] = sspSubPacket;
				this.HashedSubPackets = sspHashed;
			} else {
				SignatureSubPacket[] sspUnhashed = new SignatureSubPacket[this.UnhashedSubPackets.Length + 1];
				Array.Copy(this.HashedSubPackets, 0, sspUnhashed, 0, this.UnhashedSubPackets.Length);
				sspUnhashed[sspUnhashed.Length - 1] = sspSubPacket;
				this.UnhashedSubPackets = sspUnhashed;
			}
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// Verifies the data given as parameter with the given public key.
		/// </summary>
		/// <remarks>
		/// <para>The function calculates a message digest over the given signature
		/// data and verifies the digest with the digest stored in the
		/// signature packet.</para>
		/// <para>The results of the verify operation are directly stored
		/// in the SignatureStatus property of this class.</para>
		/// </remarks>
		/// <param name="bSignedData">The data that is to be verified.</param>
		/// <param name="pkpKey">The key that is to verify the signature</param>
		public void Verify(byte[] bSignedData, PublicKeyPacket pkpKey) {
			System.Security.Cryptography.HashAlgorithm haVerifyer;
			AsymmetricCipher acVerifyer;
			
			switch (this.HashAlgorithm) {
				case HashAlgorithms.MD5:
					haVerifyer = System.Security.Cryptography.MD5.Create();
					break;
				case HashAlgorithms.SHA1:
					haVerifyer = System.Security.Cryptography.SHA1.Create();
					break;
				default:
					throw(new System.Exception("Currently only MD5 and SHA1 are implemented as hash algorithms!"));
			}
			
			switch (this.SignatureAlgorithm) {
				case AsymAlgorithms.DSA:
					acVerifyer = new SharpPrivacy.SharpPrivacyLib.Cipher.DSA();
					break;
				case AsymAlgorithms.RSA_Encrypt_Sign:
				case AsymAlgorithms.RSA_Sign_Only:
					acVerifyer = new SharpPrivacy.SharpPrivacyLib.Cipher.RSA();
					break;
				default:
					throw(new System.Exception("Currently only DSA and RSA are implemented as signature algorithms!"));
			}
			
			byte[] bSignature = new byte[0];
			int iCounter = 0;
			if (this.Version <= SignaturePacketVersionNumbers.v3) {
				bSignature = new byte[5];
				
				bSignature[iCounter++] = (byte)this.SignatureType;
				long lTime = (dtTimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
				bSignature[iCounter++] = (byte)((lTime >> 24) & 0xFF);
				bSignature[iCounter++] = (byte)((lTime >> 16) & 0xFF);
				bSignature[iCounter++] = (byte)((lTime >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)(lTime & 0xFF);
			} else {
				//Hashed Subpackets Length
				int lHashedSubPacketLength = 0;
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					lHashedSubPacketLength += this.HashedSubPackets[i].Generate().Length;
				}
				
				bSignature = new byte[lHashedSubPacketLength + 12];
				bSignature[iCounter++] = 4; // Version
				bSignature[iCounter++] = (byte)this.SignatureType;
				bSignature[iCounter++] = (byte)this.SignatureAlgorithm;
				bSignature[iCounter++] = (byte)this.HashAlgorithm;
				
				//Hashed Subpackets
				bSignature[iCounter++] = (byte)((lHashedSubPacketLength >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)(lHashedSubPacketLength & 0xFF);
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					byte[] bSubPacket = this.HashedSubPackets[i].Generate();
					Array.Copy(bSubPacket, 0, bSignature, iCounter, bSubPacket.Length);
					iCounter += bSubPacket.Length;
				}
				
				//Final Trailer of 6 bytes
				bSignature[iCounter++] = 0x04;
				bSignature[iCounter++] = 0xFF;
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 24) & 0xFF);
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 16) & 0xFF);
				bSignature[iCounter++] = (byte)(((lHashedSubPacketLength+6) >> 8) & 0xFF);
				bSignature[iCounter++] = (byte)((lHashedSubPacketLength+6) & 0xFF);
				
			}
			
			byte[] bData = new byte[bSignedData.Length + bSignature.Length];
			Array.Copy(bSignedData, bData, bSignedData.Length);
			Array.Copy(bSignature, 0, bData, bSignedData.Length, bSignature.Length);
			
			byte[] bHash = haVerifyer.ComputeHash(bData);
			BigInteger biHash = new BigInteger(bHash);

			//PKCS1 Encode the hash
			if (this.SignatureAlgorithm != AsymAlgorithms.DSA) {
				
				// We encode the MD in this way:
				//  0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
				// PAD consists of FF bytes.
				byte[] bASN = new byte[0];
				
				switch (this.HashAlgorithm) {
					case HashAlgorithms.MD5:
						bASN = new byte[] {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
						                   0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 
						                   0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
						break;
					case HashAlgorithms.SHA1:
						bASN = new byte[] {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 
						                   0x2b, 0x0E, 0x03, 0x02, 0x1A, 0x05, 
						                   0x00, 0x04, 0x14};
						break;
				}
				
				int iFrameSize = (pkpKey.KeyMaterial[0].bitCount() + 7) / 8;
				byte[] bFrame = new byte[iFrameSize];
				int iASNCounter = 0;
				
				bFrame[iASNCounter++] = 0;
				bFrame[iASNCounter++] = 1;
				int iFFLength = iFrameSize - bHash.Length - bASN.Length - 3;
				for (int i=0; i<iFFLength; i++) {
					bFrame[iASNCounter++] = 0xFF;
				}
				bFrame[iASNCounter++] = 0;
				Array.Copy(bASN, 0, bFrame, iASNCounter, bASN.Length);
				iASNCounter += bASN.Length;
				Array.Copy(bHash, 0, bFrame, iASNCounter, bHash.Length);
				biHash = new BigInteger(bFrame);
			}
			
			if (acVerifyer.Verify(this.Signature, biHash, pkpKey)) {
				ssSignatureStatus = SignatureStatusTypes.Valid;
			} else {
				ssSignatureStatus = SignatureStatusTypes.Invalid;
			}
		}
		
		/// <summary>
		/// <para>Generates the content of the signature 
		/// packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			byte[] bData = new byte[0];
			
			int lSignatureDataLength = 0;
			for (int i=0; i<this.Signature.Length; i++) {
				lSignatureDataLength += this.Signature[i].GetMPI().Length;
			}
			
			int iCounter = 0;
			if (this.Version == SignaturePacketVersionNumbers.v3) {
				bData = new byte[lSignatureDataLength + 19];
				bData[iCounter++] = 3;
				bData[iCounter++] = 5;
				bData[iCounter++] = (byte)this.SignatureType;
				long lTime = (dtTimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
				bData[iCounter++] = (byte)((lTime >> 24) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 16) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 8) & 0xFF);
				bData[iCounter++] = (byte)(lTime & 0xFF);
				for (int i=0; i<8; i++) {
					bData[iCounter++] = (byte)((this.KeyID >> ((7-i)*8)) & 0xFF);
				}
				bData[iCounter++] = (byte)this.SignatureAlgorithm;
				bData[iCounter++] = (byte)this.HashAlgorithm;
				bData[iCounter++] = (byte)((this.SignedHash16Bit >> 8) & 0xFF);
				bData[iCounter++] = (byte)(this.SignedHash16Bit & 0xFF);
			} else if (this.Version == SignaturePacketVersionNumbers.v4) {
				//Hashed Subpackets Length
				int lHashedSubPacketLength = 0;
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					lHashedSubPacketLength += this.HashedSubPackets[i].Generate().Length;
				}
				//Unhashed Subpackets Length
				int lUnhashedSubPacketLength = 0;
				for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
					lUnhashedSubPacketLength += this.UnhashedSubPackets[i].Generate().Length;
				}

				bData = new byte[lSignatureDataLength + lHashedSubPacketLength +
								 lUnhashedSubPacketLength + 10];
				bData[iCounter++] = 4;
				bData[iCounter++] = (byte)this.SignatureType;
				bData[iCounter++] = (byte)this.SignatureAlgorithm;
				bData[iCounter++] = (byte)this.HashAlgorithm;
				
				
				//Hashed Subpackets
				bData[iCounter++] = (byte)((lHashedSubPacketLength >> 8) & 0xFF);
				bData[iCounter++] = (byte)(lHashedSubPacketLength & 0xFF);
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					byte[] bSubPacket = this.HashedSubPackets[i].Generate();
					Array.Copy(bSubPacket, 0, bData, iCounter, bSubPacket.Length);
					iCounter += bSubPacket.Length;
				}
				
				//Unhashed Subpackets
				bData[iCounter++] = (byte)((lUnhashedSubPacketLength >> 8) & 0xFF);
				bData[iCounter++] = (byte)(lUnhashedSubPacketLength & 0xFF);
				for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
					byte[] bSubPacket = this.UnhashedSubPackets[i].Generate();
					Array.Copy(bSubPacket, 0, bData, iCounter, bSubPacket.Length);
					iCounter += bSubPacket.Length;
				}
				
				bData[iCounter++] = (byte)((this.SignedHash16Bit >> 8) & 0xFF);
				bData[iCounter++] = (byte)(this.SignedHash16Bit & 0xFF);
			}

			for (int i=0; i<Signature.Length; i++) {
				byte[] bMPI = Signature[i].GetMPI();
				Array.Copy(bMPI, 0, bData, iCounter, bMPI.Length);
				iCounter += bMPI.Length;
			}
			
			this.bBody = bData;
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an SignaturePacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			Version = (SignaturePacketVersionNumbers)bData[0];
			
			if (Version == SignaturePacketVersionNumbers.v3) {
				SignatureType = (SignatureTypes)bData[2];
	
				long iTime = (long)bData[3] << 24;
				iTime ^= (long)bData[4] << 16;
				iTime ^= (long)bData[5] << 8;
				iTime ^= (long)bData[6];
				TimeCreated = new DateTime(iTime*10000000 + new DateTime(1970, 1, 1).Ticks);
				
				lKeyID = (ulong)bData[7] << 56;
				lKeyID ^= (ulong)bData[8] << 48;
				lKeyID ^= (ulong)bData[9] << 40;
				lKeyID ^= (ulong)bData[10] << 32;
				lKeyID ^= (ulong)bData[11] << 24;
				lKeyID ^= (ulong)bData[12] << 16;
				lKeyID ^= (ulong)bData[13] << 8;
				lKeyID ^= (ulong)bData[14];
				
				SignatureAlgorithm = (AsymAlgorithms)bData[15];
				HashAlgorithm = (HashAlgorithms)bData[16];
				HashedSubPackets = new SignatureSubPacket[0];
				UnhashedSubPackets = new SignatureSubPacket[0];
				
				sSignedHash16Bit = (ushort)(bData[17] << 8);
				sSignedHash16Bit ^= (ushort)(bData[18]);

				byte[] bMPIs = new byte[bData.Length - 19];
				Array.Copy(bData, 19, bMPIs, 0, bMPIs.Length);
				
				Signature = BigInteger.ParseMPIs(bMPIs);
			} else if (Version == SignaturePacketVersionNumbers.v4) {
				SignatureType = (SignatureTypes)bData[1];
				SignatureAlgorithm = (AsymAlgorithms)bData[2];
				HashAlgorithm = (HashAlgorithms)bData[3];
				
				int iHashedSubPacketLength = (bData[4] << 8) ^ (bData[5]);

				byte[] bHashedSubPackets = new byte[iHashedSubPacketLength];
				Array.Copy(bData, 6, bHashedSubPackets, 0, iHashedSubPacketLength);
				
				SignatureSubPacket sspSubPacketParser = new SignatureSubPacket();
				sspHashedSubPackets = sspSubPacketParser.ParsePackets(bHashedSubPackets);
				for (int i=0; i<sspHashedSubPackets.Length; i++) {
					if (sspHashedSubPackets[i].Type == SignatureSubPacketTypes.IssuerKeyID) {
						this.KeyID = sspHashedSubPackets[i].KeyID;
					} else if (sspHashedSubPackets[i].Type == SignatureSubPacketTypes.SignatureCreationTime) {
						this.TimeCreated = sspHashedSubPackets[i].TimeCreated;
					}
				}
				
				int iIndex = iHashedSubPacketLength + 6;
				
				bHashedPart = new byte[iIndex];
				Array.Copy(bData, 0, bHashedPart, 0, iIndex);
				
				int iUnhashedSubPacketLength = (bData[iIndex++] << 8)
							^ bData[iIndex++];
				
				byte[] bUnhashedSubPackets = new byte[iUnhashedSubPacketLength];
				Array.Copy(bData, iIndex, bUnhashedSubPackets, 0, iUnhashedSubPacketLength);
				
				sspSubPacketParser = new SignatureSubPacket();
				sspUnhashedSubPackets = sspSubPacketParser.ParsePackets(bUnhashedSubPackets);
				for (int i=0; i<sspUnhashedSubPackets.Length; i++) {
					if (sspUnhashedSubPackets[i].Type == SignatureSubPacketTypes.IssuerKeyID) {
						this.KeyID = sspUnhashedSubPackets[i].KeyID;
					} else if (sspUnhashedSubPackets[i].Type == SignatureSubPacketTypes.SignatureCreationTime) {
						this.TimeCreated = sspUnhashedSubPackets[i].TimeCreated;
					}
				}
				
				iIndex += iUnhashedSubPacketLength;
				sSignedHash16Bit = (ushort)(bData[iIndex++] << 8);
				sSignedHash16Bit ^= (ushort)(bData[iIndex++]);
				
				byte[] bMPIs = new byte[bData.Length - iIndex];
				Array.Copy(bData, iIndex, bMPIs, 0, bMPIs.Length);
				
				Signature = BigInteger.ParseMPIs(bMPIs);
			}
			
			this.bIsUpdated = false;
			return this;
		}
		
		private ulong FindIssuerKeyID() {
			if (this.Version == SignaturePacketVersionNumbers.v4) {
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.IssuerKeyID)
						return this.HashedSubPackets[i].KeyID;
				}
				for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
					if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.IssuerKeyID)
						return this.UnhashedSubPackets[i].KeyID;
				}
				return 0;
			}
			return lKeyID;
		}
		
		public ArrayList FindRevokerKeys() {
				ArrayList list = new ArrayList();
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.RevocationKey)
						list.Add(this.HashedSubPackets[i].RevocationKeyID);
				}
				for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
					if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.RevocationKey)
						list.Add(this.UnhashedSubPackets[i].RevocationKeyID);
				}
				return list;
		}

		public bool isRevocable() {
			for (int i=0; i<this.HashedSubPackets.Length; i++) {
				if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.Revocable) {
					return this.HashedSubPackets[i].Revocable;
				}
			}
			for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
				if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.Revocable)
					return this.UnhashedSubPackets[i].Revocable;
			}
			
			return true;
		}

		public byte FindReasonForRevocationCode() {
			if(this.SignatureType == SignatureTypes.CertificationRevocationSignature ||
				this.SignatureType == SignatureTypes.KeyRevocationSignature ||
				this.SignatureType == SignatureTypes.SubkeyRevocationSignature)
			{
				byte code = 0x00;
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.ReasonForRevocation) {
						code=this.HashedSubPackets[i].ReasonForRevocationCode;
						return code;
					}
				}
				for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
					if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.ReasonForRevocation) {
						code=this.UnhashedSubPackets[i].ReasonForRevocationCode;
						return code;
					}
				}
				return code;
			}
			return 0x00;
		}

		public string[] FindNotationNames() {
			int number = 0;
			for (int i=0; i<this.HashedSubPackets.Length; i++) 
				if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData)
					number++;

			for (int i=0; i<this.UnhashedSubPackets.Length; i++)
				if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData)
					number++;

			string[] name = new string[number];
			number=0;
			for (int i=0; i<this.HashedSubPackets.Length; i++)
				if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData)
					name[number++]=this.HashedSubPackets[i].NotationName;

			for (int i=0; i<this.UnhashedSubPackets.Length; i++) 
				if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData)
					name[number++]=this.UnhashedSubPackets[i].NotationName;
			
			return name;
		}

		public string FindNotationValue(string name) {
			string nvalue = null;
			for (int i=0; i<this.HashedSubPackets.Length; i++) {
				if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData) {
					if(this.HashedSubPackets[i].NotationName == name) {
						nvalue=this.HashedSubPackets[i].NotationValue;
						return nvalue;
					}
				}
			}
			for (int i=0; i<this.UnhashedSubPackets.Length; i++) {
				if (this.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.NotationData) {
					if (this.UnhashedSubPackets[i].NotationName == name) {
						nvalue=this.UnhashedSubPackets[i].NotationValue;
						return nvalue;
					}
				}
			}
			return nvalue;
		}
		
		private DateTime FindSignatureCreationTime() {
			if (this.Version == SignaturePacketVersionNumbers.v4) {
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.SignatureCreationTime)
						return this.HashedSubPackets[i].TimeCreated;
				}
				throw new Exception("This signature packet does not contain the mandatory signature creation time. Very strange!");
			}
			return dtTimeCreated;
		}
		
		public SymAlgorithms[] FindPreferedSymAlgorithms() {
			if (this.Version == SignaturePacketVersionNumbers.v4) {
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.PreferedSymmetricAlgorithms)
						return this.HashedSubPackets[i].PreferedSymAlgos;
				}
				throw new InvalidOperationException("This signature packet does not contain a prefered symmetrical algorithm list!");
			}
			throw new InvalidOperationException("This signature packet does not contain a prefered symmetrical algorithm list!");
		}
		
		public DateTime FindExpirationTime() {
			if (this.Version == SignaturePacketVersionNumbers.v4) {
				for (int i=0; i<this.HashedSubPackets.Length; i++) {
					if (this.HashedSubPackets[i].Type == SignatureSubPacketTypes.SignatureExpirationTime)
						return new DateTime(this.TimeCreated.Ticks + (this.HashedSubPackets[i].SignatureExpirationTime.Ticks - new DateTime(1970, 1, 1).Ticks));
				}
				throw new InvalidOperationException("never");
			}
			throw new InvalidOperationException("never");
		}
		
	}
}

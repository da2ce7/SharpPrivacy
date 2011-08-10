//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// TransportablePublicKey.cs: 
// 	Class for handling asymmetrically encrypted session key packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 15.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using System.Collections;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// The AsymSessionKeyPacket is a representation of an
	/// Asymmetrically encrypted sessionkey packet as specified
	/// in RFC 2440 (OpenPGP). <br></br>
	/// It makes handling the sessionkey packets easier.
	/// </summary>
	/// <remarks>
	/// The AsymSessionKeyPacket is a representation of an
	/// Asymmetrically encrypted sessionkey packet as specified
	/// in RFC 2440 (OpenPGP). <br></br>
	/// It makes handling the sessionkey packets easier.
	/// </remarks>
	public class AsymSessionKeyPacket : Packet {
		private AsymSessionKeyPacketVersionNumbers vnVersion = AsymSessionKeyPacketVersionNumbers.v3;
		private ulong lKeyID;
		private AsymAlgorithms aaPublicAlgorithm;
		private byte[] bEncodedSessionKey;
		private byte[] bSessionKey;
		private SymAlgorithms saSymmetricAlgorithm;
		private BigInteger[] biEncryptedSessionKey;
		
		/// <summary>
		/// Creates a new AsymSessionKeyPacket with the parameters
		/// in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		/// <remarks>No remarks</remarks>
		public AsymSessionKeyPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new AsymSessionKeyPacket. Format defaults
		/// to new packet format.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public AsymSessionKeyPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.AsymSessionKey;
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// The version of the session key packet.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The version of the session key packet.</value>
		public AsymSessionKeyPacketVersionNumbers Version {
			get {
				return vnVersion;
			}
		}
		
		/// <summary>
		/// The keyID to which the session key packet is encrypted
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The keyID to which the session key packet is 
		/// encrypted</value>
		public ulong KeyID {
			get {
				return lKeyID;
			}
			set {
				this.bIsUpdated = true;
				lKeyID = value;
			}
		}
		
		/// <summary>
		/// The public key (asymmetrical) algorithm used to encrypt
		/// the session key packet.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The public key (asymmetrical) algorithm used to encrypt
		/// the session key packet.</value>
		public AsymAlgorithms PublicAlgorithm {
			get {
				return aaPublicAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				aaPublicAlgorithm = value;
			}
		}
		
		/// <summary>
		/// The symmetric algorithm used to encrypt the symmetrically
		/// encrypted data packet that follows an ESKSequence (a serie
		/// of asymmetrically or symmetrically encrypted data packet.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// The symmetric algorithm used to encrypt the symmetrically
		/// encrypted data packet that follows an ESKSequence (a serie
		/// of asymmetrically or symmetrically encrypted data packet.
		/// </value>
		public SymAlgorithms SymmetricAlgorithm {
			get {
				return saSymmetricAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				saSymmetricAlgorithm = value;
			}
		}
		
		/// <summary>
		/// The session key in an encoded way (as specified in
		/// the OpenPGP RFC).
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The session key in an encoded way (as specified in
		/// the OpenPGP RFC).</value>
		public byte[] EncodedSessionKey {
			get {
				return bEncodedSessionKey;
			}
		}
		
		/// <summary>
		/// The session key as byte array.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The session key as byte array.</value>
		public byte[] SessionKey {
			get {
				return bSessionKey;
			}
			set {
				this.bIsUpdated = true;
				bSessionKey = value;
			}
		}
		
		/// <summary>
		/// The session key in an encoded AND encrypted way.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The session key in an encoded AND encrypted 
		/// way.</value>
		public BigInteger[] EncryptedSessionKey {
			get {
				return biEncryptedSessionKey;
			}
			set {
				this.bIsUpdated = true;
				biEncryptedSessionKey = value;
			}
		}
		
		/// <summary>
		/// Decodes an encoded session key and stores the result in the
		/// SessionKey property.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public void DecodeSessionKey() {
			if (bEncodedSessionKey.Length < 7) {
				throw(new Exception("Encoded sessionkey not set or invalid"));
			}
			
			//copy the sessionkey
			for (int i=2; i<bEncodedSessionKey.Length; i++) {
				if (bEncodedSessionKey[i] == 0) {
					i++;
					SymmetricAlgorithm = (SymAlgorithms)bEncodedSessionKey[i++];
					bSessionKey = new byte[bEncodedSessionKey.Length - i - 2];
					Array.Copy(bEncodedSessionKey, i, bSessionKey, 0, bEncodedSessionKey.Length - i - 2);
					i = bEncodedSessionKey.Length - 2;
					
					uint iOldChecksum = (uint)(bEncodedSessionKey[i++]) << 8;
					iOldChecksum ^= (uint)bEncodedSessionKey[i++];
					//Verify the sessionkey checksum
					uint iChecksum = 0;
					for (int j=0; j<bSessionKey.Length; j++) {
						iChecksum = (iChecksum + (uint)bSessionKey[j]) % 65536;
					}
					
					if (iOldChecksum != iChecksum) {
						throw(new Exception("Sessionkey checksum is not as expected. Someone played with the key?!"));
					}
					
					break;
				}
			}
			
		}
		
		/// <summary>
		/// Encodes the session key stored in the SessionKey property
		/// and saves the result in the EncodedSessionKey property.
		/// </summary>
		/// <param name="nKeySize">The size of the asymmetrical 
		/// key used to encrypt the symmetrical session key.</param>
		/// <remarks>No remarks</remarks>
		public void EncodeSessionKey(int nKeySize) {
			byte[] bData = new byte[(nKeySize+7)/8];
			
			if (bSessionKey.Length > bData.Length-6) {
				throw(new System.ArgumentException("Either the keylength is too short, or the session key is too long. either way: it's not possible to encode the sessionway!"));
			}
			
			uint iChecksum = 0;
			for (int i=0; i<bSessionKey.Length; i++) {
				iChecksum = (iChecksum + (uint)bSessionKey[i]) % 65536;
			}
			
			int iPos = 0;
			bData[iPos++] = 0;
			bData[iPos++] = 2;
			
			int nRandomBytes = bData.Length - 6 - bSessionKey.Length;
			System.Security.Cryptography.RandomNumberGenerator rngRandom = System.Security.Cryptography.RandomNumberGenerator.Create();
			
			byte[] bRandom = new byte[nRandomBytes];
			rngRandom.GetNonZeroBytes(bRandom);
			
			Array.Copy(bRandom, 0, bData, iPos, bRandom.Length);
			iPos += bRandom.Length;
			
			bData[iPos++] = 0;
			bData[iPos++] = (byte)saSymmetricAlgorithm;
			
			Array.Copy(bSessionKey, 0, bData, iPos, bSessionKey.Length);
			iPos += bSessionKey.Length;
			
			bData[iPos++] = (byte)((iChecksum >> 8) & 0xFF);
			bData[iPos++] = (byte)(iChecksum & 0xFF);
			
			this.bIsUpdated = true;
			bEncodedSessionKey = bData;
		}
		
		/// <summary>
		/// <para>Generates the content of the asymmetrical session 
		/// key packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			int iLength = 0;
			for (int i=0; i<biEncryptedSessionKey.Length; i++)
				iLength += biEncryptedSessionKey[i].GetMPI().Length;
			
			byte[] bData = new byte[10 + iLength];
			int iPos = 0;
			
			bData[iPos++] = (byte)this.vnVersion;
			
			bData[iPos++] = (byte)((lKeyID >> 56) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 48) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 40) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 32) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 24) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 16) & 0xFF);
			bData[iPos++] = (byte)((lKeyID >> 8) & 0xFF);
			bData[iPos++] = (byte)(lKeyID & 0xFF);
			
			bData[iPos++] = (byte)aaPublicAlgorithm;
			
			for (int i=0; i<this.biEncryptedSessionKey.Length; i++) {
				byte[] bEncryptedKey = biEncryptedSessionKey[i].GetMPI();
				Array.Copy(bEncryptedKey, 0, bData, iPos, bEncryptedKey.Length);
				iPos += bEncryptedKey.Length;
			}
			
			this.bBody = bData;
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an AsySessionKeyPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			if (bData.Length < 10) {
				throw(new System.ArgumentException("The given Packet is not a valid SessionKey packet!"));
			}
			vnVersion = (AsymSessionKeyPacketVersionNumbers)bData[0];
			lKeyID  = (ulong)bData[1] << 56;
			lKeyID ^= (ulong)bData[2] << 48;
			lKeyID ^= (ulong)bData[3] << 40;
			lKeyID ^= (ulong)bData[4] << 32;
			lKeyID ^= (ulong)bData[5] << 24;
			lKeyID ^= (ulong)bData[6] << 16;
			lKeyID ^= (ulong)bData[7] << 8;
			lKeyID ^= (ulong)bData[8];
			
			PublicAlgorithm = (AsymAlgorithms)bData[9];
			
			byte[] bMPIs = new byte[bData.Length - 10];
			Array.Copy(bData, 10, bMPIs, 0, bMPIs.Length);
			
			biEncryptedSessionKey = BigInteger.ParseMPIs(bMPIs);
			
			return this;
		}
		
		/// <summary>
		/// Encryptes the session key stored in the SessionKey property
		/// and saves the results in the EncryptedSessionKey property.
		/// </summary>
		/// <remarks>This method also calles EncodeSessionKey so that it
		/// does not have been called before calling EncryptSessionKey.
		/// <p></p>
		/// Please note: calling this function takes some time, because
		/// asymmetrical encryption takes some time!
		/// </remarks>
		/// <param name="pkpPacket">An PublicKeyPacket to which
		/// the sessionkey should be encrypted to.</param>
		public void EncryptSessionKey(PublicKeyPacket pkpPacket) {
			EncodeSessionKey(pkpPacket.KeyMaterial[0].bitCount());
			
			AsymmetricCipher acCipher = new RSA();
			switch (aaPublicAlgorithm) {
				case AsymAlgorithms.ElGama_Encrypt_Sign:
				case AsymAlgorithms.ElGamal_Encrypt_Only:
					acCipher = new ElGamal();
					break;
				
				case AsymAlgorithms.RSA_Encrypt_Only:
				case AsymAlgorithms.RSA_Encrypt_Sign:
					acCipher = new RSA();
					break;
				
				default:
					throw new System.Exception("The chosen public key algorithm is not yet implemented!");
			}
			
			this.bIsUpdated = true;
			biEncryptedSessionKey = acCipher.Encrypt(new BigInteger(this.bEncodedSessionKey), pkpPacket);
		}
		
		/// <summary>
		/// Decrypts the session key stored in the EncryptedSessionKey
		/// property and saves the decrypted key in the EncodedSessionKey
		/// property.
		/// </summary>
		/// <remarks>This function also calls DecodeSessionKey so that the
		/// decrypted and decoded sessionkey is stored in the
		/// SessionKey property.</remarks>
		/// <param name="tskKey">A transportable secret key that is used to
		/// decrypt the encrypted session key.</param>
		/// <param name="strPassphrase">The passphrase used to decrypt the
		/// encrypted key material of the given transportable secret
		/// key.</param>
		public void DecryptSessionKey(TransportableSecretKey tskKey, string strPassphrase) {
			
			AsymmetricCipher acCipher = new RSA();
			switch (aaPublicAlgorithm) {
				case AsymAlgorithms.ElGama_Encrypt_Sign:
				case AsymAlgorithms.ElGamal_Encrypt_Only:
					acCipher = new ElGamal();
					break;
				
				case AsymAlgorithms.RSA_Encrypt_Only:
				case AsymAlgorithms.RSA_Encrypt_Sign:
					acCipher = new RSA();
					break;
				
				default:
					throw new System.Exception("The chosen public key algorithm is not yet implemented!");
			}
			
			bool bFound = false;
			SecretKeyPacket skpKey = new SecretKeyPacket();
			IEnumerator ieSubkeys = tskKey.SubKeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (!(ieSubkeys.Current is SecretKeyPacket))
					throw new System.Exception("Expected a secret key packet, but did not find one!");
				
				skpKey = (SecretKeyPacket)ieSubkeys.Current;
				if (skpKey.PublicKey.KeyID == lKeyID) {
					bFound = true;
					continue;
				}
			}
			
			// check if the message was encrypted with the primary key
			if (!bFound) {
				if (tskKey.PrimaryKey.PublicKey.KeyID == lKeyID) {
					skpKey = tskKey.PrimaryKey;
				} else {
					//theoretically we should never see this exception, as
					//encrytped message makes sure we only get fitting secret
					//keys, but just in case someone calls this directly, we
					//throw an exception
					throw new System.Exception("No fitting secret key found!");
				}
			}
			
			BigInteger biKey = acCipher.Decrypt(this.biEncryptedSessionKey, skpKey, strPassphrase);
			
			this.bEncodedSessionKey = biKey.getBytes();
			DecodeSessionKey();
		}
		
		/// <summary>
		/// Returns a string representation of the packet. This is
		/// a human readable formated representation that has nothing
		/// to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the packet.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "Asymmetrically Encrypted Session Key Packet\r\n";
			strReturn += "Version: " + this.vnVersion.ToString() + "\r\n";
			strReturn += "KeyID: 0x" + this.KeyID.ToString("x") + "\r\n";
			strReturn += "Public Key Algo: " + this.aaPublicAlgorithm.ToString() + "\r\n";
			//strReturn += "Symmetric Algo: " + this.SymmetricAlgorithm.ToString() + "\r\n";
			strReturn += "Encrypted Session Key:\r\n";
			for (int i=0; i<biEncryptedSessionKey.Length; i++)
				strReturn += biEncryptedSessionKey[i].ToString(16) + "\r\n\r\n";
			
			return strReturn + "----\r\n";
			
		}
		
		
	}
}

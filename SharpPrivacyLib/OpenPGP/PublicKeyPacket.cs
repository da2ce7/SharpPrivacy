//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// PublicKeyPacket.cs: 
// 	Class for handling public key packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 20.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Security.Cryptography;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// The PublicKeyPacket class is used as representation for an 
	/// OpenPGP public key packet. It can be used to manipulate or load
	/// public keys.
	/// </summary>
	/// <remarks>No remarks</remarks>
	public class PublicKeyPacket : Packet {
		
		// Private Properties variables
		private PublicKeyPacketVersionNumbers vsVersion;
		private DateTime dtTimeCreated;
		private AsymAlgorithms aaAlgorithm;
		private ushort sValidity;
		private BigInteger[] biKeyMaterial;
		
		// Private Module variables
		private byte[] bHashMaterial;

		/// <summary>
		/// Gets or sets the version of the public key packet.
		/// </summary>
		/// <remarks>Public Key Packets can have 2 versions: v3 and v4.
		/// v4 are state of the art packets.</remarks>
		/// <value>The version of the public key packet.</value>
		public PublicKeyPacketVersionNumbers Version {
			get {
				return vsVersion;
			}
			set {
				this.bIsUpdated = true;
				vsVersion = value;
			}
		}
		
		/// <summary>
		/// Returns the Fingerprint of the currently loaded key.
		/// </summary>
		/// <remarks>
		/// A V4 fingerprint is the 160-bit SHA-1 hash of the
		/// one-octet Packet Tag, followed by the two-octet packet
		/// length, followed by the entire Public Key packet
		/// starting with the version field.</para>
		/// <para>The fingerprint of a V3 key is formed by hashing the
		/// body (but not the two-octet length) of the MPIs that
		/// form the key material (public modulus n, followed by
		/// exponent e) with MD5.</para>
		/// <para>This property is readonly!!!</para>
		/// </remarks>
		/// <value>The fingerprint of the key as a BigInteger.</value>
		public BigInteger Fingerprint {
			get {
				CreateHashMaterial();
				System.Security.Cryptography.HashAlgorithm haHash = MD5.Create();
				if (this.Version == PublicKeyPacketVersionNumbers.v3) {
					haHash = MD5.Create();
				} else if (this.Version == PublicKeyPacketVersionNumbers.v4) {
					haHash = SHA1.Create();
				}
				byte[] bHash = haHash.ComputeHash(bHashMaterial);
				return new BigInteger(bHash);
			}
		}
		
		/// <summary>
		/// Gets the KeyID of the currently loaded Key. 
		/// </summary>
		/// <remarks>The KeyID
		/// consists of the loworder 64 bits of the fingerprint for a
		/// v4 key, and of the loworder 64 bits of the public modulus
		/// of a v3 key.</remarks>
		/// <value>The KeyID of the currently loaded Key.</value>
		public ulong KeyID {
			get {
				ulong lKeyID = 0;
				if (this.Version == PublicKeyPacketVersionNumbers.v3) {
					//public modulus is keymaterial[0]
					byte[] bModulus = biKeyMaterial[0].getBytes();
					for (int i=0; i<8; i++) {
						lKeyID ^= (ulong)((bModulus[bModulus.Length - (i + 1)] & 0xFF)) << (i*8);	
					}
				} else if (this.Version == PublicKeyPacketVersionNumbers.v4) {
					byte[] bFingerprint = this.Fingerprint.getBytes();
					for (int i=0; i<8; i++) {
						lKeyID ^= (ulong)((bFingerprint[bFingerprint.Length - (i + 1)] & 0xFF)) << (i*8);	
					}
				}
				return lKeyID;
			}
		}
		
		/// <summary>
		/// Gets or sets the time when the key was created.
		/// </summary>
		/// <remarks>No remarks.</remarks>
		/// <value>The time when the key was created.</value>
		public DateTime TimeCreated {
			get {
				return dtTimeCreated;
			}
			set {
				dtTimeCreated = value;
				this.bIsUpdated = true;
			}
		}

		/// <summary>
		/// Gets or sets the public key algorithm for which the public 
		/// key contains key material.
		/// </summary>
		/// <remarks>See <see cref="AsymAlgorithms">AsymAlgorithms</see> 
		/// for a list of valid algorithms.</remarks>
		/// <value>The public key algorithm for which the public key 
		/// contains key material.</value>
		public AsymAlgorithms Algorithm {
			get {
				return aaAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				aaAlgorithm = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the validity of a v3 public key.
		/// </summary>
		/// <remarks>In v3 packets, this property gives the validity of
		/// the key in days. In v4 packets, this property must
		/// be omitted.</remarks>
		/// <value>The validity of a v3 public key.</value>
		public ushort Validity {
			get {
				return sValidity;
			}
			set {
				this.bIsUpdated = true;
				sValidity = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an array of biginteger that composes the
		/// private key material.
		/// </summary>
		/// <remarks>
		/// The order of the components in the array is according to
		/// the OpenPGP RFC.
		/// </summary>
		/// <value>An array of biginteger that composes the
		/// private key material.</value>
		public BigInteger[] KeyMaterial {
			get {
				return biKeyMaterial;
			}
			set {
				this.bIsUpdated = true;
				biKeyMaterial = value;
			}
		}
		
		/// <summary>
		/// Creates a new PublicKeyPacket with the parameters
		/// in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		/// <remarks>No remarks.</remarks>
		public PublicKeyPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new public key packet. Format defaults
		/// to new packet format.
		/// </summary>
		/// <remarks>No remarks.</remarks>
		public PublicKeyPacket() : this(false) {}
		
		/// <summary>
		/// Creates a new public key packet. Format defaults
		/// to new packet format.
		/// </summary>
		/// <param name="bIsSubkey">if you want to create a
		/// public subkey packet, this parameter has to be true.
		/// </param>
		/// <remarks>No remarks.</remarks>
		public PublicKeyPacket(bool bIsSubkey) {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			if (bIsSubkey) 
				ctContent = ContentTypes.PublicSubkey;
			else
				ctContent = ContentTypes.PublicKey;
			this.bIsUpdated = true;
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
			
			strReturn += "PublicKeyPacket:\r\n";
			strReturn += "Version: " + Version.ToString() + "\r\n";
			strReturn += "Algorithm: " + Algorithm.ToString() + "\r\n";
			strReturn += "Time Created: " + TimeCreated.ToLocalTime() + "\r\n";
			strReturn += "Fingerprint: 0x" + Fingerprint.ToString(16) + "\r\n";
			strReturn += "KeyID: " + KeyID.ToString() + "\r\n";
			strReturn += "Key Material:\r\n";
			
			for (int i=0; i<KeyMaterial.Length; i++)
				strReturn += KeyMaterial[i].ToString(16) + "\r\n\r\n";
			
			return strReturn + "----\r\n\r\n";
		}
		
		private void CreateHashMaterial() {
			if (this.Version == PublicKeyPacketVersionNumbers.v3) {
				
				//first get the length we need to dimensionate the array
				long lLength = 0;
				for (int i=0; i<biKeyMaterial.Length; i++) {
					byte[] bMPI = biKeyMaterial[i].GetMPI();
					lLength += bMPI.Length - 2;
				}
				bHashMaterial = new byte[lLength];
				int iPosition = 0;
				for (int i=0; i<biKeyMaterial.Length; i++) {
					byte[] bMPI = biKeyMaterial[i].GetMPI();
					Array.Copy(bMPI, 2, bHashMaterial, iPosition, bMPI.Length - 2);
					iPosition += bMPI.Length - 2;
				}
			} else if (this.Version == PublicKeyPacketVersionNumbers.v4) {
				CraftContent();
				bHashMaterial = new byte[bBody.Length + 3];
				bHashMaterial[0] = 0x99;
				bHashMaterial[1] = (byte)((bBody.Length >> 8) & 0xFF);
				bHashMaterial[2] = (byte)(bBody.Length & 0xFF);
				Array.Copy(bBody, 0, bHashMaterial, 3, bBody.Length);
			}
		}
		
		/// <summary>
		/// <para>Generates the content of the public key 
		/// packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			long lLength = 0;
			byte[] bData = new byte[0];
			for (int i=0; i<biKeyMaterial.Length; i++) {
				lLength += biKeyMaterial[i].GetMPI().Length;
			}
			
			int iCounter = 0;
			if (this.Version == PublicKeyPacketVersionNumbers.v3) {
				//length of a packet is length of key material
				// plus 5 bytes
				bData = new byte[lLength + 8];
				bData[iCounter++] = (byte)Version;
				long lTime = (this.TimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
				bData[iCounter++] = (byte)((lTime >> 24) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 16) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 8) & 0xFF);
				bData[iCounter++] = (byte)(lTime & 0xFF);

				bData[iCounter++] = (byte)((Validity >> 8) & 0xFF);
				bData[iCounter++] = (byte)(Validity & 0xFF);
				
			} else if (this.Version == PublicKeyPacketVersionNumbers.v4) {
				//length of a packet is length of key material
				// plus 7 bytes
				bData = new byte[lLength + 6];
				bData[iCounter++] = (byte)Version;
				
				long lTime = (this.TimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
				bData[iCounter++] = (byte)((lTime >> 24) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 16) & 0xFF);
				bData[iCounter++] = (byte)((lTime >> 8) & 0xFF);
				bData[iCounter++] = (byte)(lTime & 0xFF);
				
			}
			
			//the rest is the same for both v3 and v4 keys
			bData[iCounter++] = (byte)Algorithm;
			
			for (int i=0; i<biKeyMaterial.Length; i++) {
				byte[] bMPI = biKeyMaterial[i].GetMPI();
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
		/// <returns>Returns an PublicKeyPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			Version = (PublicKeyPacketVersionNumbers)bData[0];

			uint iTime = (uint)bData[1] << 24;
			iTime ^= (uint)bData[2] << 16;
			iTime ^= (uint)bData[3] << 8;
			iTime ^= (uint)bData[4];
			TimeCreated = new DateTime(((long)iTime)*10000000 + new DateTime(1970, 1, 1).Ticks);
			
			int iIndex = 5;
			if ((Version == PublicKeyPacketVersionNumbers.v3) || (Version == PublicKeyPacketVersionNumbers.v2)) {
				Validity = (ushort)(bData[5] << 8);
				Validity ^= bData[6];
				iIndex = 7;
			}
			
			Algorithm = (AsymAlgorithms)bData[iIndex++];
			
			byte[] bMPIs = new byte[bData.Length - iIndex];
			Array.Copy(bData, iIndex, bMPIs, 0, bMPIs.Length);
			/* usually we could just use BigInteger.parseMPIs(bMPIs)
			 * to parse the key material, but public key packets
			 * can also be inside of secret key packets, so just parsing
			 * the rest of the array would case wrong keymaterial to
			 * be read.
			 * workaround: parse as many MPIs as the algorithm
			 * requires
			 */
			
			if (Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
			    Algorithm == AsymAlgorithms.RSA_Encrypt_Sign ||
			    Algorithm == AsymAlgorithms.RSA_Sign_Only) 
			{
				this.biKeyMaterial = BigInteger.ParseMPIs(bMPIs, 2);
			} else if (Algorithm == AsymAlgorithms.DSA) {
				this.biKeyMaterial = BigInteger.ParseMPIs(bMPIs, 4);
			} else if (Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
			           Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only)
			{
				this.biKeyMaterial = BigInteger.ParseMPIs(bMPIs, 3);
			}
			
			this.CraftContent();
			
			this.bIsUpdated = false;
			return this;
			
		}
	}
}

//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// TransportablePublicKey.cs: 
// 	Class for handling secret key packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 17.02.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.IO;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// This class represents an OpenPGP secret key packet. It contains
	/// secret data used for decrypting files.
	/// </summary>
	public class SecretKeyPacket : Packet {
		private PublicKeyPacket pkpPublicKey;
		private bool bIsEncrypted;
		private SymAlgorithms saSymmetricalAlgorithm;
		private String2KeySpecifier bS2KSpecifier;
		private byte[] bInitialVector;
		private byte[] bEncryptedKeyMaterial;
		private BigInteger[] biDecryptedKeyMaterial;
		private ushort sChecksum;
		
		/// <summary>
		/// Creates a new SecretKeyPacket with the parameters
		/// in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		public SecretKeyPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.S2KSpecifier = new String2KeySpecifier();
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new secret key packet. Format defaults
		/// to new packet format.
		/// </summary>
		public SecretKeyPacket() : this(false) {}
		
		/// <summary>
		/// Creates a new secret key packet. Format defaults
		/// to new packet format.
		/// </summary>
		/// <param name="bIsSubkey">Has to be true, if you want
		/// to create a secret subkey packet.</param>
		public SecretKeyPacket(bool bIsSubkey) {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			bIsEncrypted = true;
			bS2KSpecifier = new String2KeySpecifier();
			bS2KSpecifier.HashAlgorithm = HashAlgorithms.SHA1;
			bS2KSpecifier.Type = String2KeySpecifierTypes.IteraterSaltedS2K;
			bS2KSpecifier.Count = 96;
			
			byte[] bSalt = new byte[8];
			System.Security.Cryptography.RandomNumberGenerator rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
			rngRand.GetBytes(bSalt);
			
			S2KSpecifier.Salt = 0;
			S2KSpecifier.Salt = ((ulong)bSalt[0] << 56) ^ ((ulong)bSalt[1] << 48) ^ 
			                    ((ulong)bSalt[2] << 40) ^ ((ulong)bSalt[3] << 32) ^ 
			                    ((ulong)bSalt[3] << 24) ^ ((ulong)bSalt[5] << 16) ^ 
			                    ((ulong)bSalt[6] << 8) ^ (ulong)bSalt[7];
			
			if (bIsSubkey)
				ctContent = ContentTypes.SecretSubkey;
			else
				ctContent = ContentTypes.SecretKey;
			
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// Gets the decrypted key material. Readonly!
		/// </summary>
		/// <value>The decrypted key material.</value>
		public BigInteger[] DecryptedKeyMaterial {
			get {
				if (this.IsEncrypted == true) {
					throw(new Exception("Can't get the decrypted key material this way for an encrypted key. This is problably a bug in the program!"));
				}
				return biDecryptedKeyMaterial;
			}
		}
		
		/// <summary>
		/// Every secret key has to contain a public key. This property
		/// gets or sets the public key fitting the the secret key packet.
		/// </summary>
		/// <value>The public key fitting the the secret key packet.</value>
		public PublicKeyPacket PublicKey {
			get {
				return pkpPublicKey;
			}
			set {
				this.bIsUpdated = true;
				pkpPublicKey = value;
			}
		}
		
		/// <summary>
		/// Gets or sets a boolean value indicating wether
		/// the secret key material should be encrypted.
		/// </summary>
		/// <remarks>It is definitly recommended to use
		/// encrypted key material!</remarks>
		/// <value>a boolean value indicating wether
		/// the secret key material should be encrypted.</value>
		public bool IsEncrypted {
			get {
				return bIsEncrypted;
			}
			set {
				this.bIsUpdated = true;
				bIsEncrypted = value;
			}
		}
		
		public SymAlgorithms SymmetricalAlgorithm {
			get {
				return saSymmetricalAlgorithm;
			}
			set {
				saSymmetricalAlgorithm = value;
			}
		}
		
		public String2KeySpecifier S2KSpecifier {
			get {
				return bS2KSpecifier;
			}
			set {
				this.bIsUpdated = true;
				bS2KSpecifier = value;
			}
		}
		
		public byte[] InitialVector {
			get {
				return bInitialVector;
			}
			set {
				this.bIsUpdated = true;
				bInitialVector = value;
			}
		}
		
		public byte[] EncryptedKeyMaterial {
			get {
				return bEncryptedKeyMaterial;
			}
			set {
				this.bIsUpdated = true;
				bEncryptedKeyMaterial = value;
			}
		}
		
		public void EncryptKeyMaterial(BigInteger[] biGivenKeyMaterial, string strPassphrase) {
			this.biDecryptedKeyMaterial = biGivenKeyMaterial;
			if (!bIsEncrypted)
				return;
			
			if (this.PublicKey.Version == PublicKeyPacketVersionNumbers.v4) {
			
				int iKeyMaterialLength = 0;
				for (int i=0; i<this.biDecryptedKeyMaterial.Length; i++)
					iKeyMaterialLength += biDecryptedKeyMaterial[i].GetMPI().Length;
				
				byte[] bData = new byte[iKeyMaterialLength + 2];
				int iPos = 0;
				for (int i=0; i<this.biDecryptedKeyMaterial.Length; i++) {
					byte[] bMPI = biDecryptedKeyMaterial[i].GetMPI();
					Array.Copy(bMPI, 0, bData, iPos, bMPI.Length);
					iPos += bMPI.Length;
				}
				
				int iChecksum = 0;
				for (int i=0; i<bData.Length - 2; i++)
					iChecksum = (iChecksum + bData[i]) % 65536;
				
				bData[iPos++] = (byte)((iChecksum >> 8) & 0xFF);
				bData[iPos++] = (byte)(iChecksum & 0xFF);

				SharpPrivacy.SharpPrivacyLib.Cipher.SymmetricAlgorithm saAlgo;
				switch (this.SymmetricalAlgorithm) {
					case SymAlgorithms.AES128:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 128;
						break;
					case SymAlgorithms.AES192:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 192;
						break;
					case SymAlgorithms.AES256:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 256;
						break;
					case SymAlgorithms.Triple_DES:
						saAlgo = TripleDES.Create();
						saAlgo.KeySize = 192;
						break;
					case SymAlgorithms.CAST5:
						saAlgo = CAST5.Create();
						break;
					
					default:
						throw(new System.NotSupportedException("Sorry, but the Algorithm that was used to encrypt the secret key data is not (yet) supported by SharpPrivacy!"));
				}
				
				saAlgo.Mode = CipherMode.CFB;
				saAlgo.Key = this.S2KSpecifier.GetKey(strPassphrase, saAlgo.KeySize);
				saAlgo.IV = this.InitialVector;
				saAlgo.Padding = PaddingMode.None;
				
				byte[] bOutput = new byte[bData.Length];
				ICryptoTransform ictEnc = saAlgo.CreateEncryptor();
				ictEnc.TransformBlock(bData, 0, bData.Length, ref bOutput, 0);
				
				byte[] bTmp = new byte[bData.Length];
				Array.Copy(bOutput, 0, bTmp, 0, bTmp.Length);
				bOutput = bTmp;
				
				if (bOutput.Length != bData.Length)
					throw new Exception("Encryption of the secret Key material did not work correctly. Look at the file SecretKeyPacket, function EncryptKeyMaterial()");
				
				bEncryptedKeyMaterial = bOutput;
			} else {
				throw new Exception("Sorry, but we don't support v3 secret keys so far!");
			}
			this.bIsUpdated = true;
		}
		
		public BigInteger[] GetDecryptedKeyMaterial(string strPassphrase) {
			BigInteger[] biKeys = new BigInteger[0];
			if (this.bIsEncrypted) {
				SharpPrivacy.SharpPrivacyLib.Cipher.SymmetricAlgorithm saAlgo;
				switch (this.SymmetricalAlgorithm) {
					case SymAlgorithms.AES128:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 128;
						break;
					case SymAlgorithms.AES192:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 192;
						break;
					case SymAlgorithms.AES256:
						saAlgo = Rijndael.Create();
						saAlgo.BlockSize = 128;
						saAlgo.KeySize = 256;
						break;
					case SymAlgorithms.Triple_DES:
						saAlgo = TripleDES.Create();
						saAlgo.KeySize = 192;
						break;
					case SymAlgorithms.CAST5:
						saAlgo = CAST5.Create();
						break;
					
					default:
						throw(new System.NotSupportedException("Sorry, but the Algorithm that was used to encrypt the secret key data is not (yet) supported by SharpPrivacy!"));
				}
				
				saAlgo.Mode = CipherMode.CFB;
				saAlgo.Key = this.S2KSpecifier.GetKey(strPassphrase, saAlgo.KeySize);
				
				if (this.PublicKey.Version == PublicKeyPacketVersionNumbers.v3) {
					throw(new System.NotImplementedException("Sorry, but we have not yet implemented the decryption of v3 keys!"));
				} else if (this.PublicKey.Version == PublicKeyPacketVersionNumbers.v4) {
					//In v4 keys, everything - including mpi headers and checksum
					//is encrypted. Should be a heck of a lot easier than for
					//v3 keys.
					
					saAlgo.IV = this.InitialVector;
					saAlgo.Padding = PaddingMode.None;
					
					byte[] bOutput = new byte[this.bEncryptedKeyMaterial.Length];
					ICryptoTransform ictDec = saAlgo.CreateDecryptor();
					ictDec.TransformBlock(bEncryptedKeyMaterial, 0, bEncryptedKeyMaterial.Length, ref bOutput, 0);

					int iCurrentChecksum = 0;
					for (int i=0; i<bOutput.Length; i++)
						iCurrentChecksum = (iCurrentChecksum + bOutput[i]) % 65536;
					
					if (pkpPublicKey.Algorithm == AsymAlgorithms.DSA ||
					    pkpPublicKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
					    pkpPublicKey.Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only) 
					{
						biKeys = new BigInteger[1];
						try {
							biKeys = BigInteger.ParseMPIs(bOutput, 1);
						} catch (Exception) {
							throw new Exception("Invalid Passphrase!");
						}
					} else if (pkpPublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
					           pkpPublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign ||
					           pkpPublicKey.Algorithm == AsymAlgorithms.RSA_Sign_Only)
					{
						biKeys = new BigInteger[4];
						try {
							biKeys = BigInteger.ParseMPIs(bOutput, 4);
						} catch (Exception) {
							throw new Exception("Invalid Passphrase!");
						}
					}
					
					
				}
			} else {
				//Key Material is not encrypted anyway
				biKeys = this.DecryptedKeyMaterial;
			}
			
			return biKeys;
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
			
			strReturn += "SecretKeyPacket:\r\n";
			
			strReturn += "Internal PublicKeyPacket:\r\n";
			strReturn += this.PublicKey.ToString();
			
			if (this.IsEncrypted) {
				strReturn += this.S2KSpecifier.ToString();
				strReturn += "Symmetric Algorithm: " + this.SymmetricalAlgorithm.ToString() + "\r\n";
				strReturn += "Initial Vector: ";
				for (int i=0; i<this.InitialVector.Length; i++) 
					strReturn += ":" + this.InitialVector[i].ToString("x");
				
				strReturn += "\r\nKey Material:\r\n";
				for (int i=0; i<this.EncryptedKeyMaterial.Length; i++) {
					strReturn += ":" + this.EncryptedKeyMaterial[i].ToString("x");
				}
				strReturn += "\r\n";
			} else {
				strReturn += "Decrypted Key Material:\r\n";
				for (int i=0; i<DecryptedKeyMaterial.Length; i++)
					strReturn += DecryptedKeyMaterial[i].ToString(16) + "\r\n\r\n";
			}
			
			
			return strReturn + "----\r\n\r\n";
		}
		
		/// <summary>
		/// <para>Generates the content of the secret 
		/// key packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			byte[] bPublicKey = pkpPublicKey.Body;
			int iPos = 0;
			byte[] bData = new byte[0];
			
			if (this.PublicKey.Version == PublicKeyPacketVersionNumbers.v4) {
			
				if (bIsEncrypted) {
					byte[] bS2K = this.bS2KSpecifier.CraftContent();
					bData = new byte[bPublicKey.Length + bS2K.Length + bEncryptedKeyMaterial.Length + bInitialVector.Length + 2];
					Array.Copy(bPublicKey, 0, bData, iPos, bPublicKey.Length);
					iPos += bPublicKey.Length;
					bData[iPos++] = 255;
					bData[iPos++] = (byte)saSymmetricalAlgorithm;
					Array.Copy(bS2K, 0, bData, iPos, bS2K.Length);
					iPos += bS2K.Length;
					Array.Copy(bInitialVector, 0, bData, iPos, bInitialVector.Length);
					iPos += bInitialVector.Length;
					Array.Copy(bEncryptedKeyMaterial, 0, bData, iPos, bEncryptedKeyMaterial.Length);
					iPos += bEncryptedKeyMaterial.Length;
				} else {
					int iKeyMaterialLength = 0;
					for (int i=0; i<biDecryptedKeyMaterial.Length; i++)
						iKeyMaterialLength += biDecryptedKeyMaterial[i].GetMPI().Length;
					
					bData = new byte[bPublicKey.Length + 3 + iKeyMaterialLength];
					Array.Copy(bPublicKey, 0, bData, iPos, bPublicKey.Length);
					iPos += bPublicKey.Length;
					bData[iPos++] = 0;
					int iKeyMaterialStart = iPos;
					for (int i=0; i<biDecryptedKeyMaterial.Length; i++) {
						byte[] bMPI = biDecryptedKeyMaterial[i].GetMPI();
						Array.Copy(bMPI, 0, bData, iPos, bMPI.Length);
						iPos += bMPI.Length;
					}
					
					int iChecksum = 0;
					for (int i=iKeyMaterialStart; i<iPos; i++)
						iChecksum = (iChecksum + bData[i]) % 65536;
					
					bData[iPos++] = (byte)((iChecksum >> 8) & 0xFF);
					bData[iPos++] = (byte)(iChecksum & 0xFF);
				}
			} else {
				throw new Exception("Sorry, but we don't yet support v3 secret keys!");
			}
			
			this.bBody = bData;
			
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an SecretKeyPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			PublicKey = new PublicKeyPacket();
			PublicKey = (PublicKeyPacket)PublicKey.ParsePacket(bData);
			
			int iPos = this.PublicKey.Length;
			
			if (bData[iPos] == 255) {
				this.bIsEncrypted = true;
				iPos++;
				
				saSymmetricalAlgorithm = (SymAlgorithms)bData[iPos++];
				
				//String2Key Specifier expected
				// a S2K specifier is at max 11 bytes long
				byte[] bS2k = new byte[11];
				Array.Copy(bData, iPos, bS2k, 0, bS2k.Length);
				this.S2KSpecifier.ParseSpecifier(bS2k);
				iPos += S2KSpecifier.CraftContent().Length;
				
				//Parse Initial Vector
				int iBlockSize = CipherHelper.CipherBlockSize(saSymmetricalAlgorithm);
				this.InitialVector = new byte[iBlockSize];
				Array.Copy(bData, iPos, bInitialVector, 0, iBlockSize);
				iPos += iBlockSize;
				
				//Parse Encrypted MPIs (including checksum!!!)
				this.bEncryptedKeyMaterial = new byte[bData.Length - iPos];
				Array.Copy(bData, iPos, bEncryptedKeyMaterial, 0, bData.Length - iPos);
			} else if (bData[iPos] == 0) {
				this.bIsEncrypted = false;
				iPos++;
				
				//Parse unencrypted MPIs
				byte[] bMPIs = new byte[bData.Length - iPos - 2];
				Array.Copy(bData, iPos, bMPIs, 0, bMPIs.Length);
				
				biDecryptedKeyMaterial = BigInteger.ParseMPIs(bMPIs);
				
				iPos += bMPIs.Length;
				this.sChecksum = (ushort)(bData[iPos++] << 8);
				this.sChecksum ^= (ushort)bData[iPos];
				
				//validate checksum
				int iCurrentChecksum = 0;
				for (int i=0; i<bMPIs.Length; i++)
					iCurrentChecksum = (iCurrentChecksum + bMPIs[i]) % 65536;
				
				if (iCurrentChecksum != sChecksum)
					throw(new Exception("Key checksum is not correct. Someone played with the key?!"));
					
			} else {
				//Encrypted in some strange way. We're not going
				//to support this
				throw(new Exception("This secret key is encrypted in some strange way. Sorry, but we're not going to support this. Get a real key!"));
			}
			
			
			this.bIsUpdated = false;
			return this;
		}
		
	}
}


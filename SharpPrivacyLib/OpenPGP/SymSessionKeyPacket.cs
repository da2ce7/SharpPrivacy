//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SymSessionKeyPacket.cs: 
// 	Class for handling symmetrically encrypted session keys.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 02.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {

	public class SymSessionKeyPacket : Packet {
		
		private SymSessionKeyPacketVersionNumbers ssVersion;
		private SymAlgorithms saAlgorithm;
		private String2KeySpecifier s2kSpecifier;
		private byte[] bEncryptedSessionKey;
		
		public SymSessionKeyPacketVersionNumbers Version {
			get {
				return ssVersion;
			}
			set {
				this.bIsUpdated = true;
				ssVersion = value;
			}
		}
		
		public SymAlgorithms Algorithm {
			get {
				return saAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				saAlgorithm = value;
			}
		}
		
		public String2KeySpecifier S2KSpecifier {
			get {
				return s2kSpecifier;
			}
			set {
				this.bIsUpdated = true;
				s2kSpecifier = value;
			}
		}
		
		public byte[] EncryptedSessionKey {
			get {
				return bEncryptedSessionKey;
			}
			set {
				this.bIsUpdated = true;
				bEncryptedSessionKey = value;
			}
		}
		
		
		/// <summary>
		/// Creates a new SymSessionKeyPacket with 
		/// the parameters in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		public SymSessionKeyPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			EncryptedSessionKey = new byte[0];
			s2kSpecifier = new String2KeySpecifier();
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new symmetrical session key packet. Format defaults
		/// to new packet format.
		/// </summary>
		public SymSessionKeyPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.SymSessionKey;
			this.bEncryptedSessionKey = new byte[0];
			
			s2kSpecifier = new String2KeySpecifier();
			s2kSpecifier.Type = String2KeySpecifierTypes.IteraterSaltedS2K;
			s2kSpecifier.Count = 96;
			
			byte[] bSalt = new byte[8];
			System.Security.Cryptography.RandomNumberGenerator rngRand = System.Security.Cryptography.RandomNumberGenerator.Create();
			rngRand.GetBytes(bSalt);
			
			S2KSpecifier.Salt = 0;
			S2KSpecifier.Salt = ((ulong)bSalt[0] << 56) ^ ((ulong)bSalt[1] << 48) ^ 
			                    ((ulong)bSalt[2] << 40) ^ ((ulong)bSalt[3] << 32) ^ 
			                    ((ulong)bSalt[3] << 24) ^ ((ulong)bSalt[5] << 16) ^ 
			                    ((ulong)bSalt[6] << 8) ^ (ulong)bSalt[7];
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
			string strReturn = "Symmetrically Encrypted Session-Key:\r\n";
			
			strReturn += "Version: " + this.Version.ToString() + "\r\n";
			strReturn += "Sym. Algorithm: " + this.Algorithm.ToString() + "\r\n";
			strReturn += "String2Key Specifier: " + this.s2kSpecifier.ToString() + "\r\n";
			strReturn += "Encrypted Session Key: ";
			for (int i=0; i<this.bEncryptedSessionKey.Length; i++) {
				string strByte = bBody[i].ToString("x");
				if (strByte.Length < 2) {
					strByte = "0" + strByte;
				}
				strReturn += ":" + strByte;
			}
			strReturn += "\r\n----\r\n\r\n";
			return strReturn;
		}
		
		/// <summary>
		/// <para>Generates the content of the symmetrical session 
		/// key packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			byte[] bData = new byte[0];
			
			int iPos = 0;
			byte[] bS2K = s2kSpecifier.CraftContent();
			bData[iPos++] = (byte)Version;
			bData[iPos++] = (byte)Algorithm;
			Array.Copy(bS2K, 0, bData, 2, bS2K.Length);
			iPos += bS2K.Length;
			
			if (this.bEncryptedSessionKey.Length > 0)
				Array.Copy(bEncryptedSessionKey, 0, bData, iPos, bEncryptedSessionKey.Length);
			
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an SymSessionKeyPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			if (bData.Length < 4)
				throw new ArgumentException("Invalid Packet!");
			
			Version = (SymSessionKeyPacketVersionNumbers)bData[0];
			Algorithm = (SymAlgorithms)bData[1];
			
			int ls2kLength = s2kSpecifier.Length(bData[2]);
			if (ls2kLength == 0)
				throw new ArgumentException("Invalid Packet!");
			
			if (bData.Length < ls2kLength+2)
				throw new ArgumentException("Invalid Packet!");
			
			byte[] bS2K = new byte[ls2kLength];
			Array.Copy(bData, 2, bS2K, 0, ls2kLength);
			s2kSpecifier.ParseSpecifier(bS2K);
			
			//check if there is an encrypted session key attached
			if (bData.Length > 2+ls2kLength) {
				bEncryptedSessionKey = new byte[bData.Length - (ls2kLength + 2)];
				Array.Copy(bData, 2+ls2kLength, bEncryptedSessionKey, 0, bEncryptedSessionKey.Length);
			} else {
				bEncryptedSessionKey = new byte[0];
			}
			
			this.bIsUpdated = false;
			return this;
			
		}
		 
		
	}
	
}

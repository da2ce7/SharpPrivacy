//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// String2KeySpecifier.cs: 
// 	Class for handling string to key specifiers.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 18.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Security.Cryptography;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {

	public class String2KeySpecifier : object {
		private String2KeySpecifierTypes s2kType;
		private HashAlgorithms haHashAlgorithm;
		private ulong lSalt;
		private byte bCount;
		
		public String2KeySpecifier(byte[] bSpecifier) {
			ParseSpecifier(bSpecifier);
		}
		
		public String2KeySpecifier() {
			
		}
		
		public HashAlgorithms HashAlgorithm {
			get {
				return haHashAlgorithm;
			}
			set {
				haHashAlgorithm = value;
			}
		}
		
		public String2KeySpecifierTypes Type {
			get {
				return s2kType;
			}
			set {
				s2kType = value;
			}
		}
		
		public ulong Salt {
			get {
				return lSalt;
			}
			set {
				lSalt = value;
			}
		}
		
		public byte Count {
			get {
				return bCount;
			}
			set {
				bCount = value;
			}
		}
		
		public byte[] CraftContent() {
			byte[] bData = new byte[0];
			if (this.Type == String2KeySpecifierTypes.SimpleS2K) {
				bData = new byte[2];
				bData[0] = 0x00;
				bData[1] = (byte)this.HashAlgorithm;
			} else if (this.Type == String2KeySpecifierTypes.SimpleS2K) {
				bData = new byte[10];
				bData[0] = (byte)this.Type;
				bData[1] = (byte)this.HashAlgorithm;
				
				bData[2] = (byte)((lSalt >> 56) & 0xFF);
				bData[3] = (byte)((lSalt >> 48) & 0xFF);
				bData[4] = (byte)((lSalt >> 40) & 0xFF);
				bData[5] = (byte)((lSalt >> 32) & 0xFF);
				bData[6] = (byte)((lSalt >> 24) & 0xFF);
				bData[7] = (byte)((lSalt >> 16) & 0xFF);
				bData[8] = (byte)((lSalt >> 8) & 0xFF);
				bData[9] = (byte)(lSalt & 0xFF);
			} else {
				bData = new byte[11];
				bData[0] = (byte)this.Type;
				bData[1] = (byte)this.HashAlgorithm;
				
				bData[2] = (byte)((lSalt >> 56) & 0xFF);
				bData[3] = (byte)((lSalt >> 48) & 0xFF);
				bData[4] = (byte)((lSalt >> 40) & 0xFF);
				bData[5] = (byte)((lSalt >> 32) & 0xFF);
				bData[6] = (byte)((lSalt >> 24) & 0xFF);
				bData[7] = (byte)((lSalt >> 16) & 0xFF);
				bData[8] = (byte)((lSalt >> 8) & 0xFF);
				bData[9] = (byte)(lSalt & 0xFF);
				bData[10] = this.bCount;
			}
			
			return bData;
		}
		
		/// <summary>
		/// Returns a string representation of the String2Key specifier.
		/// This is a human readable formated representation that has 
		/// nothing to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the specifier.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "";
			
			if (this.Type == String2KeySpecifierTypes.IteraterSaltedS2K) {
				strReturn += "Iterated and Salted String2Key Specifier:\r\n";
			} else if (this.Type == String2KeySpecifierTypes.SaltedS2K) {
				strReturn += "Salted String2Key Specifier:\r\n";
			} else if (this.Type == String2KeySpecifierTypes.SimpleS2K) {
				strReturn += "Simple String2Key Specifier:\r\n";
			}
			
			strReturn += "Salt: " + this.Salt.ToString("x") + "\r\n";
			strReturn += "Iterationcount: " + this.Count.ToString() + "\r\n\r\n";
			
			return strReturn;
		}
		
		public int Length(byte bType) {
			String2KeySpecifierTypes s2kstType = (String2KeySpecifierTypes)bType;
			switch (s2kstType) {
				case String2KeySpecifierTypes.SimpleS2K:
					return 2;
				case String2KeySpecifierTypes.SaltedS2K:
					return 10;
				case String2KeySpecifierTypes.IteraterSaltedS2K:
					return 11;
			}
			
			return 0;
		}
		
		public void ParseSpecifier(byte[] bSpecifier) {
			if (bSpecifier.Length < 2) {
				throw(new System.ArgumentException("Not a valid String2Key specifier!"));
			}
			this.Type = (String2KeySpecifierTypes)bSpecifier[0];
			this.HashAlgorithm = (HashAlgorithms)bSpecifier[1];
			
			if (this.Type == String2KeySpecifierTypes.SaltedS2K ||
			    this.Type == String2KeySpecifierTypes.IteraterSaltedS2K) {
				if (bSpecifier.Length < 10) {
					throw(new System.ArgumentException("Not a valid String2Key specifier!"));
				}
				lSalt = ((ulong)bSpecifier[2]) << 56;
				lSalt ^= ((ulong)bSpecifier[3]) << 48;
				lSalt ^= ((ulong)bSpecifier[4]) << 40;
				lSalt ^= ((ulong)bSpecifier[5]) << 32;
				lSalt ^= ((ulong)bSpecifier[6]) << 24;
				lSalt ^= ((ulong)bSpecifier[7]) << 16;
				lSalt ^= ((ulong)bSpecifier[8]) << 8;
				lSalt ^= ((ulong)bSpecifier[9]);
			}
			
			if (this.Type == String2KeySpecifierTypes.IteraterSaltedS2K) {
				if (bSpecifier.Length < 11) {
					throw(new System.ArgumentException("Not a valid String2Key specifier!"));
				}
				bCount = bSpecifier[10];
			}
		}
		
		public byte[] GetKey(string strPassphrase, int nKeySize) {
			System.Security.Cryptography.HashAlgorithm haHash;
			switch (this.HashAlgorithm) {
				case HashAlgorithms.MD5:
					haHash = MD5.Create();
					break;
				case HashAlgorithms.SHA1:
					haHash = SHA1.Create();
					break;
				default:
					throw(new Exception("Currently only MD5 and SHA1 are implemented as Hash algorithms!"));
			}
			
			byte[] bPassphrase = System.Text.Encoding.UTF8.GetBytes(strPassphrase);

			int iPosition = 0;
			int iCount = 0;
			byte[] bReturn = new byte[(nKeySize + 7) / 8];
			while (iPosition < bReturn.Length) {
				int iOffset = 0;
				byte[] bHashContext = new byte[0];
				if (this.Type == String2KeySpecifierTypes.SimpleS2K) {
					bHashContext = new byte[bPassphrase.Length + iCount];
				} else {
					iOffset = 8;
					bHashContext = new byte[bPassphrase.Length + iCount + iOffset];
				}
				
				
				for (int i=0; i<iCount; i++) {
					bHashContext[i] = 0;
				}
				
				if (this.Type == String2KeySpecifierTypes.SaltedS2K ||
				    this.Type == String2KeySpecifierTypes.IteraterSaltedS2K) {
					bHashContext[iCount] = (byte)((lSalt >> 56) & 0xFF);
					bHashContext[iCount + 1] = (byte)((lSalt >> 48) & 0xFF);
					bHashContext[iCount + 2] = (byte)((lSalt >> 40) & 0xFF);
					bHashContext[iCount + 3] = (byte)((lSalt >> 32) & 0xFF);
					bHashContext[iCount + 4] = (byte)((lSalt >> 24) & 0xFF);
					bHashContext[iCount + 5] = (byte)((lSalt >> 16) & 0xFF);
					bHashContext[iCount + 6] = (byte)((lSalt >> 8) & 0xFF);
					bHashContext[iCount + 7] = (byte)(lSalt & 0xFF);
				}
				
				Array.Copy(bPassphrase, 0, bHashContext, iCount + iOffset, bPassphrase.Length);
				
				if (this.Type == String2KeySpecifierTypes.IteraterSaltedS2K) {
					uint lIterationCount = (uint)((16 + (bCount & 15))) << ((bCount >> 4) + 6);
					if (lIterationCount < bPassphrase.Length + 8) {
						lIterationCount = (uint)bHashContext.Length;
					}
					byte[] bOldHashContext = new byte[bHashContext.Length];
					Array.Copy(bHashContext, bOldHashContext, bHashContext.Length);
					bHashContext = new byte[lIterationCount + iCount];
					Array.Copy(bOldHashContext, bHashContext, bOldHashContext.Length);
					
					byte[] bOneIteration = new byte[bOldHashContext.Length - iCount];
					Array.Copy(bOldHashContext, iCount, bOneIteration, 0, bOldHashContext.Length - iCount);
					
					int iIterationPos = bOldHashContext.Length;
					while (iIterationPos < (bHashContext.Length)) {
						if (bHashContext.Length < (iIterationPos + bOneIteration.Length)) {
							Array.Copy(bOneIteration, 0, bHashContext, iIterationPos, bHashContext.Length - iIterationPos);
						} else {
							Array.Copy(bOneIteration, 0, bHashContext, iIterationPos, bOneIteration.Length);
						}
						iIterationPos += bOneIteration.Length;
					}
				}
				byte[] bHash = haHash.ComputeHash(bHashContext);
				
				if (bHash.Length > (bReturn.Length - iPosition)) {
					Array.Copy(bHash, 0, bReturn, iPosition, bReturn.Length - iPosition);
				} else {
					Array.Copy(bHash, 0, bReturn, iPosition, bHash.Length);
				}
				iPosition += bHash.Length;
				iCount++;
			}
			
			return bReturn;
		}
		
		
	}
	
}

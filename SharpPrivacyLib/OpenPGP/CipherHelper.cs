//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// CipherHelper.cs: 
// 	This class provides various static helper functions for work with
//	ciphers.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 04.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	public class CipherHelper {
		
		public static int CipherBlockSize(SymAlgorithms saAlgo) {
			int iBlockSize = 0;
			switch (saAlgo) {
				case SymAlgorithms.AES128:
				case SymAlgorithms.AES192:
				case SymAlgorithms.AES256:
					iBlockSize = 16;
					break;
				case SymAlgorithms.CAST5:
					iBlockSize = 8;
					break;
				case SymAlgorithms.Triple_DES:
					iBlockSize = 8;
					break;
			}
			return iBlockSize;
		}
	
		public static int CipherKeySize(SymAlgorithms saAlgo) {
			int iKeySize = 0;
			switch (saAlgo) {
				case SymAlgorithms.AES128:
					iKeySize = 128;
					break;
				case SymAlgorithms.AES192:
					iKeySize = 192;
					break;
				case SymAlgorithms.AES256:
					iKeySize = 256;
					break;
				case SymAlgorithms.CAST5:
					iKeySize = 128;
					break;
				case SymAlgorithms.Triple_DES:
					iKeySize = 192;
					break;
			}
			return iKeySize;
		}
		
		public static SymmetricAlgorithm CreateSymAlgorithm(SymAlgorithms saAlgo) {
			SymmetricAlgorithm saReturn;
			
			switch (saAlgo) {
				case SymAlgorithms.AES128:
					saReturn = Rijndael.Create();
					saReturn.BlockSize = 128;
					saReturn.KeySize = 128;
					break;
				case SymAlgorithms.AES192:
					saReturn = Rijndael.Create();
					saReturn.BlockSize = 128;
					saReturn.KeySize = 192;
					break;
				case SymAlgorithms.AES256:
					saReturn = Rijndael.Create();
					saReturn.BlockSize = 128;
					saReturn.KeySize = 256;
					break;
				case SymAlgorithms.CAST5:
					saReturn = CAST5.Create();
					break;
				case SymAlgorithms.Triple_DES:
					saReturn = TripleDES.Create();
					break;
				default:
					throw new System.Security.Cryptography.CryptographicException("The algorithm is not supported!");
			}
			
			return saReturn;
		}
		
	}
}

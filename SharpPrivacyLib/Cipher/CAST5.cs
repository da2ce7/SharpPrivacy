//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// CAST5.cs: 
// 	Class for encrypting and decrypting using the CAST5 cipher.
//
// Parts of this code rely on portions of the go-mono implemenation
// of the cipher. These parts are copyright of their respective
// owners (see also the below header).
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 21.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.Cipher to
//                SharpPrivacy.SharpPrivacyLib.Cipher
//
// (C) 2003, Daniel Fabian
//

//
// System.Security.Cryptography.RC2.cs
//
// Authors: 
//	Andrew Birkett (andy@nobugs.org)
//	Sebastien Pouliot (spouliot@motus.com)
//          

using System;

namespace SharpPrivacy.SharpPrivacyLib.Cipher {

	public abstract class CAST5 : SymmetricAlgorithm {

		public static new CAST5 Create() {
			return (CAST5)Activator.CreateInstance(Type.GetType("SharpPrivacy.SharpPrivacyLib.Cipher.CAST5CryptoServiceProvider"), null);
		}
		
		protected int EffectiveKeySizeValue;

		public virtual int EffectiveKeySize {
			get {
				if (EffectiveKeySizeValue == 0)
					return KeySizeValue;
				else
					return EffectiveKeySizeValue;
			}
			set { 
				if (!IsLegalKeySize(LegalKeySizesValue, value))
					throw new System.Security.Cryptography.CryptographicException("key size not supported by algorithm");
				EffectiveKeySizeValue = value; 
			}
		}

		// Overridden, which makes me suspect it changes effective keysize too?
		public override int KeySize {
			get { 
				return KeySizeValue;
			}
			set { 
				KeySizeValue = value;
			}
		}
				
		public CAST5() {
			KeySizeValue = 128;
			BlockSizeValue = 64;
			FeedbackSizeValue = 64;
			
			//valid keysizes are 40 to 128 bit in 8 bit steps
			LegalKeySizesValue = new KeySizes[1];
			LegalKeySizesValue[0] = new KeySizes(40, 128, 8);
			
			LegalBlockSizesValue = new KeySizes[1];
			LegalBlockSizesValue[0] = new KeySizes(64, 64, 0);
		}
		
		
	}
}

//
// System.Security.Cryptography.Rijndael.cs
//
// Authors: Dan Lewis (dihlewis@yahoo.co.uk)
//          Andrew Birkett (andy@nobugs.org)
//
// (C) 2002
//
// Modified by Daniel Fabian to fit SharpPrivacy's needs.
// This file is part of the SharpPrivacy source code contribution.
// Get get the original SymmetricAlgorithm class, please visit the
// mono project at http://www.go-mono.com.
//

using System;

namespace SharpPrivacy.SharpPrivacyLib.Cipher {
	
	public abstract class Rijndael : SymmetricAlgorithm {

		public static new Rijndael Create () {
			return (Rijndael)Activator.CreateInstance(Type.GetType("SharpPrivacy.SharpPrivacyLib.Cipher.RijndaelManaged"), null);
		}

		public Rijndael () {
			KeySizeValue = 256;
			BlockSizeValue = 128;
			FeedbackSizeValue = 128;
	
			LegalKeySizesValue = new KeySizes[1];
			LegalKeySizesValue[0] = new KeySizes(128, 256, 64);

			LegalBlockSizesValue = new KeySizes[1];
			LegalBlockSizesValue[0] = new KeySizes(128, 256, 64);
		}
	}
}

//
// System.Security.Cryptography CipherMode enumeration
//
// Authors:
//   Matthew S. Ford (Matthew.S.Ford@Rose-Hulman.Edu)
//
// Copyright 2001 by Matthew S. Ford.
//
// Modified by Daniel Fabian to fit SharpPrivacy's needs.
// This file is part of the SharpPrivacy source code contribution.
// Get get the original SymmetricAlgorithm class, please visit the
// mono project at http://www.go-mono.com.
//


namespace SharpPrivacy.SharpPrivacyLib.Cipher {

	/// <summary>
	/// Block cipher modes of operation.
	/// </summary>
	// [Serializable]
	public enum CipherMode {
		CBC = 0x1, // Cipher Block Chaining
		ECB, // Electronic Codebook
		OFB, // Output Feedback
		CFB, // Cipher Feedback
		CTS, // Cipher Text Stealing
		OpenPGP_CFB
	}
}


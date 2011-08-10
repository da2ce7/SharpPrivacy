//
// System.Security.Cryptography KeySizes Class implementation
//
// Author:
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
	/// This class represents valid ranges of key sizes for ciphers.  It is also used to represent block sizes in the same fashion for block ciphers.
	/// </summary>
	public class KeySizes {
		private int _maxSize;
		private int _minSize;
		private int _skipSize;

		/// <summary>
		/// Creates a new KeySizes object.
		/// </summary>
		/// <param name="minSize">The minimum size key allowed for this cipher in bits.</param>
		/// <param name="maxSize">The maximum size key allowed for this cipher in bits.</param>
		/// <param name="skipSize">The jump/skip between the valid key sizes in bits.</param>
		public KeySizes (int minSize, int maxSize, int skipSize) {
			_maxSize = maxSize;
			_minSize = minSize;
			_skipSize = skipSize;
		}
		
		/// <summary>
		/// Returns the maximum valid key size in bits;
		/// </summary>
		public int MaxSize {
			get {
				return _maxSize;
			}
		}
		
		/// <summary>
		/// Returns the minimum valid key size in bits;
		/// </summary>
		public int MinSize {
			get {
				return _minSize;
			}
		}
		
		/// <summary>
		/// Returns the skip between valid key sizes in bits;
		/// </summary>
		public int SkipSize {
			get {
				return _skipSize;
			}
		}		
	}
}


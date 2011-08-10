//
// Mono.Math.Prime.Generator.NextPrimeFinder.cs - Prime Generator
//
// Authors:
//	Ben Maurer
//
// Copyright (c) 2003 Ben Maurer. All rights reserved
//
// Modified by Daniel Fabian to fit SharpPrivacy's needs.
// This file is part of the SharpPrivacy source code contribution.
// Get get the original BigInteger class, please visit the
// mono project at http://www.go-mono.com.

using System;

namespace SharpPrivacy.SharpPrivacyLib.Cipher.Math.Prime.Generator {

	/// <summary>
	/// Finds the next prime after a given number.
	/// </summary>
	[CLSCompliant(false)]
	public class NextPrimeFinder : SequentialSearchPrimeGeneratorBase {
		
		protected override BigInteger GenerateSearchBase (int bits, object Context) {
			if (Context == null) throw new ArgumentNullException ("Context");
			BigInteger ret = new BigInteger ((BigInteger)Context);
			ret.setBit (0);
			return ret;
		}
	}
}

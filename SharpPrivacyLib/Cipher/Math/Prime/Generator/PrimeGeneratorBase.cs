//
// Mono.Math.Prime.Generator.PrimeGeneratorBase.cs - Abstract Prime Generator
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

	[CLSCompliant(false)]
	public abstract class PrimeGeneratorBase {
		private ConfidenceFactor cfConfidence = ConfidenceFactor.Medium;

		public virtual ConfidenceFactor Confidence {
			get {
				return cfConfidence;
			}
			set {
				cfConfidence = value;
			}
		}

		public virtual Prime.PrimalityTest PrimalityTest {
			get {
				return new Prime.PrimalityTest (PrimalityTests.SmallPrimeSppTest);
			}
		}

		public virtual int TrialDivisionBounds {
			get { 
				return 4000;
			}
		}

		/// <summary>
		/// Performs primality tests on bi, assumes trial division has been done.
		/// </summary>
		/// <param name="bi">A BigInteger that has been subjected to and passed trial division</param>
		/// <returns>False if bi is composite, true if it may be prime.</returns>
		/// <remarks>The speed of this method is dependent on Confidence</remarks>
		protected bool PostTrialDivisionTests (BigInteger bi) {
			return PrimalityTest (bi, this.Confidence);
		}

		public abstract BigInteger GenerateNewPrime (int bits);
	}
}

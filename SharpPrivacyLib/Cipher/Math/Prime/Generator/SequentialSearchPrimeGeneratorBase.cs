//
// Mono.Math.Prime.Generator.SequentialSearchPrimeGeneratorBase.cs - Prime Generator
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
using SharpPrivacy.SharpPrivacyLib.Cipher.Math.Prime;

namespace SharpPrivacy.SharpPrivacyLib.Cipher.Math.Prime.Generator {
	
	[CLSCompliant(false)]
	public class SequentialSearchPrimeGeneratorBase : PrimeGeneratorBase {

		protected virtual BigInteger GenerateSearchBase(int bits, object Context) {
			BigInteger ret = BigInteger.genRandom(bits);
			ret.setBit (0);
			return ret;
		}


		public override BigInteger GenerateNewPrime(int bits) {
			return GenerateNewPrime(bits, null);
		}


		public virtual BigInteger GenerateNewPrime(int bits, object Context) {
			//
			// STEP 1. Find a place to do a sequential search
			//
			BigInteger curVal = GenerateSearchBase (bits, Context);

			const uint primeProd1 = 3u* 5u * 7u * 11u * 13u * 17u * 19u * 23u * 29u;

			uint pMod1 = curVal % primeProd1;

			int DivisionBound = TrialDivisionBounds;
			uint[] SmallPrimes = BigInteger.smallPrimes;
			PrimalityTest PostTrialDivisionTest = this.PrimalityTest;
			//
			// STEP 2. Search for primes
			//
			while (true) {
				pMod1 += 2;
				if (pMod1 >= primeProd1) pMod1 -= primeProd1;
				curVal.Incr2 ();
				
				//
				// STEP 2.1 Sieve out numbers divisible by the first 9 primes
				//
				if (pMod1 %  3 == 0) continue;
				if (pMod1 %  5 == 0) continue;
				if (pMod1 %  7 == 0) continue;
				if (pMod1 % 11 == 0) continue;
				if (pMod1 % 13 == 0) continue;
				if (pMod1 % 17 == 0) continue;
				if (pMod1 % 19 == 0) continue;
				if (pMod1 % 23 == 0) continue;
				if (pMod1 % 29 == 0) continue;
				
				//
				// STEP 2.2 Sieve out all numbers divisible by the primes <= DivisionBound
				//
				bool bPrime = true;
				for (int p = 9; p < SmallPrimes.Length && SmallPrimes [p] <= DivisionBound; p++) {
					if (curVal % SmallPrimes [p] == 0) {
						bPrime = false;
						break;
					}
				}

				if (!bPrime) continue;

				//
				// STEP 2.3 Is the potential prime acceptable?
				//
				if (!IsPrimeAcceptable (curVal, Context)) continue;
				
				//
				// STEP 2.4 Filter out all primes that pass this step with a primality test
				//
				if (PrimalityTest (curVal, Confidence)) 
					return curVal;
			}
		}

		protected virtual bool IsPrimeAcceptable (BigInteger bi, object Context) {
			return true;
		}
	}
}

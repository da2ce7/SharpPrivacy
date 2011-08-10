//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// ElGamal.cs: 
// 	Class for encrypting and decrypting using the El Gamal cipher.
//  Signing and Verifying have not yet been implemented.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 11.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.Cipher to
//                SharpPrivacy.SharpPrivacyLib.Cipher
//
// (C) 2003, Daniel Fabian
//
using System;
using System.Security.Cryptography;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.Cipher {
	
	
	/// <summary>
	/// This class is used for creating ElGamal keys, encrypting and decrypting,
	/// and signing and verifying with the ElGamal algorithm.
	/// </summary>
	/// <remarks>
	/// This class is used for creating ElGamal keys, encrypting and decrypting,
	/// and signing and verifying with the ElGamal algorithm.
	/// </remarks>
	public class ElGamal : AsymmetricCipher {

		private struct EG_Public_Key {
			public BigInteger p;	    /* prime */
			public BigInteger g;	    /* group generator */
			public BigInteger y;	    /* g^x mod p */
		}
		
		private struct EG_Secret_Key {
			public BigInteger p;	    /* prime */
			public BigInteger g;	    /* group generator */
			public BigInteger y;	    /* g^x mod p */
			public BigInteger x;	    /* secret exponent */
		}
		
		private BigInteger[][] biGeneratedKey;
		public BigInteger[][] GetGeneratedKey() {
			return this.biGeneratedKey;
		}
		
		
		/// <summary>
		/// Creates a new ElGamal secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.
		/// </summary>
		/// <remarks>
		/// Creates a new ElGamal secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is p, g, y
		/// The order of the secret components is x.
		/// </remarks>
		/// <param name="nbits">The size of the key in bits.</param>
		/// <returns>A new ElGamal secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is p, g, y
		/// The order of the secret components is x.
		/// </returns>
		public override BigInteger[][] Generate(int nBits) {
			EG_Secret_Key eskKey = GenerateKey(nBits);
			
			biGeneratedKey = new BigInteger[2][];
			biGeneratedKey[0] = new BigInteger[3];
			biGeneratedKey[0][0] = eskKey.p;
			biGeneratedKey[0][1] = eskKey.g;
			biGeneratedKey[0][2] = eskKey.y;
			
			biGeneratedKey[1] = new BigInteger[1];
			biGeneratedKey[1][0] = eskKey.x;
			
			return biGeneratedKey;
		}
		
		private EG_Secret_Key GenerateKey(int nBits){
			BigInteger q = new BigInteger();
			BigInteger p;
			BigInteger g;
			BigInteger gPowTwo;
			BigInteger gPowQ;
			EG_Secret_Key eskKey = new EG_Secret_Key();
			
			/*
			// construct a prime p = 2q + 1
			do {
				q = BigInteger.genRandom(nBits - 1);
				System.Windows.Forms.Application.DoEvents();
				p = (2*q) + 1;
			} while ((!p.isProbablePrime()) || (!q.isProbablePrime()));
			*/
			
			q = BigInteger.genPseudoPrime(nBits - 1);
			p = BigInteger.genPseudoPrime(nBits);
			
			// find a generator
			do {
				g = new BigInteger();
				g = BigInteger.genRandom(nBits - 1);
				gPowTwo = g.modPow(new BigInteger(2), p);
				gPowQ = g.modPow(q, p);
			} while ((gPowTwo == 1) || (gPowQ == 1));
			
			BigInteger x;
			
			do {
				x = new BigInteger();
				x = BigInteger.genRandom(nBits);
			} while (x >= p-1);
			
			BigInteger y = g.modPow(x, p);
			
			eskKey.p = p;
			eskKey.g = g;
			eskKey.x = x;
			eskKey.y = y;
			
			return eskKey;
			
		}
		
		/// <summary>
		/// Secret key operation. Decrypts biCipher with the keydata
		/// in the given secret key packet.
		/// </summary>
		/// <param name="biInput">The ciphertext that is about to
		/// be decrypted</param>
		/// <param name="skpKey">The secret key packet with the key
		/// material for the decryption</param>
		/// <param name="strPassphrase">The passphrase for the 
		/// keymaterial</param>
		/// <returns>The decrypted ciphertext.</returns>
		/// <remarks>No remarks.</remarks>
		public override BigInteger Decrypt(BigInteger[] biInput, SecretKeyPacket skpKey, string strPassphrase) {
			BigInteger[] biKeyMaterial = skpKey.GetDecryptedKeyMaterial(strPassphrase);
			EG_Secret_Key eskKey = new EG_Secret_Key();
			eskKey.x = biKeyMaterial[0];
			eskKey.p = skpKey.PublicKey.KeyMaterial[0];
			eskKey.g = skpKey.PublicKey.KeyMaterial[1];
			eskKey.y = skpKey.PublicKey.KeyMaterial[2];
			
			if (biInput.Length != 2) 
				throw new ArgumentException("biInput is not an ElGamal encrypted Packet");
			
			BigInteger B = biInput[0];
			BigInteger c = biInput[1];
			
			BigInteger z = B.modPow(eskKey.x, eskKey.p).modInverse(eskKey.p);
			
			BigInteger output = (z * c) % eskKey.p;
			
			return output;
			
		}
		
		/// <summary>
		/// Public key operation. Encrypts biInput with the keydata
		/// in the given public key packet.
		/// </summary>
		/// <param name="biInput">The plaintext that is about to
		/// be encrypted</param>
		/// <param name="pkpKey">The public key packet with the key
		/// material for the encryption</param>
		/// <returns>The encrypted ciphertext.</returns>
		/// <remarks>No remarks.</remarks>
		public override BigInteger[] Encrypt(BigInteger biInput, PublicKeyPacket pkpKey) {
			EG_Public_Key epkKey = new EG_Public_Key();
			epkKey.p = pkpKey.KeyMaterial[0];
			epkKey.g = pkpKey.KeyMaterial[1];
			epkKey.y = pkpKey.KeyMaterial[2];
			
			BigInteger k = new BigInteger();
			
			//Random number needed for encryption
			k = BigInteger.genRandom(epkKey.p.bitCount()-1);
			
			while (k > (epkKey.p-1)) {
				k = new BigInteger();
				k = BigInteger.genRandom(epkKey.p.bitCount()-1);
			}
			
			BigInteger B = epkKey.g.modPow(k, epkKey.p);
			BigInteger c = epkKey.y.modPow(k, epkKey.p);
			c = (biInput * c) % epkKey.p;
			//BigInteger c = (biInput * epkKey.y.modPow(k, epkKey.p)) % epkKey.p;
			
			BigInteger[] biOutput = new BigInteger[2];
			
			biOutput[0] = B;
			biOutput[1] = c;
			
			return biOutput;
			
		}
		
		public override BigInteger[] Sign(BigInteger biHash, SecretKeyPacket spkKey, string strPassphrase) {
			throw new System.NotImplementedException("Signatures with ElGamal keys are not yet implemented!");
		}
		
		public override bool Verify(BigInteger[] biSignature, BigInteger biHash, PublicKeyPacket pkpKey) {
			throw new System.NotImplementedException("Signatures with ElGamal keys are not yet implemented!");
		}
		
		
		
	}
	
}

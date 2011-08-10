//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// RSA.cs: 
// 	Class for encrypting, decrypting, signing and verifying
//	using the RSA cipher.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.Cipher to
//                SharpPrivacy.SharpPrivacyLib.Cipher
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;

namespace SharpPrivacy.SharpPrivacyLib.Cipher {
	
	
	/// <summary>
	/// This class is used for creating RSA keys, encrypting and decrypting,
	/// and signing and verifying with the RSA algorithm.
	/// </summary>
	/// <remarks>
	/// This class is used for creating RSA keys, encrypting and decrypting,
	/// and signing and verifying with the RSA algorithm.
	/// </remarks>
	public class RSA : AsymmetricCipher {
		
		private BigInteger[][] biGeneratedKey;

		private struct RSA_Public_Key {
			public BigInteger n;		// public modulus
			public BigInteger e;		// public exponent
		}
		
		private struct RSA_Secret_Key {
			public BigInteger n;	    // public modulus
			public BigInteger e;	    // public exponent
			public BigInteger d;	    // exponent
			public BigInteger p;	    // prime  p.
			public BigInteger q;	    // prime  q.
			public BigInteger u;	    // inverse of p mod q.
		}
	
		/// <summary>
		/// Default constructor - initializes all fields to default values
		/// </summary>
		/// <remarks>No remarks</remarks>
		public RSA() {
		}
		
		private RSA_Secret_Key ParseSecretKey(SecretKeyPacket skpKey, string strPassphrase) {
			RSA_Secret_Key rskKey = new RSA_Secret_Key();
			
			rskKey.n = skpKey.PublicKey.KeyMaterial[0];
			rskKey.e = skpKey.PublicKey.KeyMaterial[1];
			
			BigInteger[] biSecretKeyMaterial = skpKey.GetDecryptedKeyMaterial(strPassphrase);
			
			rskKey.d = biSecretKeyMaterial[0];
			rskKey.p = biSecretKeyMaterial[1];
			rskKey.q = biSecretKeyMaterial[2];
			rskKey.u = biSecretKeyMaterial[3];
			
			return rskKey;
		}
		
		public BigInteger[][] GetGeneratedKey() {
			return this.biGeneratedKey;
		}
		
		/// <summary>
		/// Returns a 2 dimensional array of BigIntegers, where
		/// return[0] are the public key components of an rsa key
		/// and return[1] are the secret components.
		/// </summary>
		/// <remarks>No remarks</remarks>
		private BigInteger[][] ParseSecretKey(RSA_Secret_Key rskKey) {
			BigInteger[][] biReturn = new BigInteger[2][];
			
			biReturn[0] = new BigInteger[2];
			biReturn[0][0] = rskKey.n;
			biReturn[0][1] = rskKey.e;
			
			biReturn[1] = new BigInteger[4];
			biReturn[1][0] = rskKey.d;
			biReturn[1][1] = rskKey.p;
			biReturn[1][2] = rskKey.q;
			biReturn[1][3] = rskKey.u;
			
			return biReturn;
		}
		
		/// <summary>
		/// Creates a new RSA secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.
		/// </summary>
		/// <remarks>
		/// Creates a new RSA secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is n, e.
		/// The order of the secret components is d, p,
		/// q and u.
		/// </remarks>
		/// <param name="nbits">The size of the key in bits.</param>
		/// <returns>A new RSA secret key as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is n, e.
		/// The order of the secret components is d, p,
		/// q and u.</returns>
		/// <exception cref="System.ArgumentException">Throws an
		/// Argumentexception if the keysize is not between 768
		/// and 4096 bits.</exception>
		public override BigInteger[][] Generate(int nbits) {
			BigInteger p, q; /* the two primes */
			BigInteger d;    /* the private key */
			BigInteger u;
			BigInteger t1, t2;
			BigInteger n = new BigInteger();    /* the public key */
			BigInteger e;    /* the exponent */
			BigInteger phi;  /* helper: (p-1)(q-1) */
			BigInteger g;
			BigInteger f;
			Random rand = new Random();
			
			if ((nbits < 768) || (nbits > 4096))
				throw new ArgumentException("Only keysizes betwen 768 and 4096 bit are allowed!");
			
			/* make sure that nbits is even so that we generate p, q of equal size */
			if ( (nbits&1)==1 )
				nbits++; 
			
			do {
				/* select two (very secret) primes */
				p = new BigInteger();
				q = new BigInteger();
				
				p = BigInteger.genPseudoPrime(nbits / 2);
				q = BigInteger.genPseudoPrime(nbits / 2);

				/* p shall be smaller than q (for calc of u)*/
				if (q > p) {
					BigInteger tmp = p;
					p = q;
					q = tmp;
				}

				/* calculate the modulus */
				n = p * q;
			} while ( n.bitCount() != nbits );
			
			/* calculate Euler totient: phi = (p-1)(q-1) */
			t1 = p - new BigInteger(1);
			t2 = q - new BigInteger(1);
			phi = t1 * t2;
			
			g = t1.gcd(t2);
			f = phi / g;
			
			/* find an public exponent.
			We use 41 as this is quite fast and more secure than the
			commonly used 17.
			*/
			
			e = new BigInteger(41);
			t1 = e.gcd(phi);
			if( t1 != new BigInteger(1) ) {
				e = new BigInteger(257);
				t1 = e.gcd(phi);
				if( t1 != new BigInteger(1) ) {
					e = new BigInteger(65537);
					t1 = e.gcd(phi);
					
					/* (while gcd is not 1) */
					while( t1 != new BigInteger(1) ) { 
						e += 2;
						t1 = e.gcd(phi);
					}
				}
			}
			
			/* calculate the secret key d = e^1 mod phi */
			d = e.modInverse(f);

			/* calculate the inverse of p and q (used for chinese remainder theorem)*/
			u = p.modInverse(q);

			RSA_Secret_Key sk = new RSA_Secret_Key();
			
			sk.n = n;
			sk.e = e;
			sk.p = p;
			sk.q = q;
			sk.d = d;
			sk.u = u;
			
			this.biGeneratedKey = ParseSecretKey(sk);
			
			return this.biGeneratedKey;
			
			/* now we can test our keys (this should never fail!) */
			// test_keys( sk, nbits - 64 );
		}
		

		/****************
		 * Test wether the secret key is valid.
		 * Returns: true if this is a valid key.
		 */
		private bool CheckKey(RSA_Secret_Key sk) {
			BigInteger temp = new BigInteger();
			
			// - e*d mod (p - 1) = 1
			if ((sk.e*sk.d) % (sk.p - 1) != 1)
				return false;
			
			// - e*d mod (q - 1) = 1
			if ((sk.e*sk.d) % (sk.q - 1) != 1)
				return false;
			
			// - pInv * p (mod q) = 1
			if (((sk.p.modInverse(sk.q) * sk.q) % sk.q) != 1)
				return false;

			// - n (from the record of the public key) = p*q
			if (sk.p * sk.q != sk.n)
				return false;
			
			return true;			
		}
		
		/// <summary>
		/// Public key operation. Encrypt biPlain with the keydata
		/// in the given public key packet. Result of c = m^e mod n
		/// is returned.
		/// </summary>
		/// <param name="biPlain">The plaintext that is about to
		/// be encrypted</param>
		/// <param name="pkpKey">The public key packet with the key
		/// material for the encryption</param>
		/// <returns>c = m^e mod n, the encrypted plaintext. The return
		/// value is given as an array of biginteger. The length of the 
		/// array is 1 and only return[0] has a value.</returns>
		/// <remarks>No remarks.</remarks>
		public override BigInteger[] Encrypt(BigInteger biPlain, PublicKeyPacket pkpKey) {
			RSA_Public_Key rpkKey = new RSA_Public_Key();
			
			if ((pkpKey.Algorithm != AsymAlgorithms.RSA_Encrypt_Only) &&
			    (pkpKey.Algorithm != AsymAlgorithms.RSA_Encrypt_Sign)) {
				throw new System.ArgumentException("This public key is not supposed to be used for RSA encryption.");
			}
			if (pkpKey.KeyMaterial.Length != 2) {
				throw new System.ArgumentException("This is not a valid RSA Key");
			}
			
			rpkKey.n = pkpKey.KeyMaterial[0];
			rpkKey.e = pkpKey.KeyMaterial[1];
			
			return Encrypt(biPlain, rpkKey);
			
		}
		
		private BigInteger[] Encrypt(BigInteger biPlain, RSA_Public_Key rpkKey) {
			if ((rpkKey.e == 0) || (rpkKey.n == 0))
				throw new System.ArgumentException("This is not a valid public key");

			BigInteger biCipher = biPlain.modPow(rpkKey.e, rpkKey.n);
			BigInteger[] biOutput = new BigInteger[1];
			biOutput[0] = biCipher;
			
			return biOutput;
		}
		
		/// <summary>
		/// Secret key operation. Decrypts biCipher with the keydata
		/// in the given secret key packet.
		/// </summary>
		/// <param name="biCipher">The ciphertext that is about to
		/// be decrypted</param>
		/// <param name="skpKey">The secret key packet with the key
		/// material for the decryption</param>
		/// <param name="strPassphrase">The passphrase for the 
		/// keymaterial</param>
		/// <returns>The decrypted ciphertext.</returns>
		/// <remarks>No remarks.</remarks>
		public override BigInteger Decrypt(BigInteger[] biCipher, SecretKeyPacket skpKey, string strPassphrase) {
			RSA_Secret_Key skey = new RSA_Secret_Key();
			
			skey = ParseSecretKey(skpKey, strPassphrase);
			
			//check if someone mangled with the key
			if (!CheckKey(skey))
				throw(new Exception("This key does not fullfill the requirements of a valid RSA key. Please check if someone messed with your keys!"));
			
			if ((skey.d == 0) || (skey.n == 0))
				throw new System.ArgumentException("This is not a valid secret key");

			BigInteger biPlain = biCipher[0].modPow(skey.d, skey.n);
			
			return biPlain;
		}
		
		/// <summary>
		/// Secret key operation. Signs biHash with the keydata
		/// in the given secret key packet.
		/// </summary>
		/// <param name="biHash">The hash value of a message that is about to
		/// be signed</param>
		/// <param name="skpKey">The secret key packet with the key
		/// material for the signature</param>
		/// <param name="strPassphrase">The passphrase for the 
		/// keymaterial</param>
		/// <returns>The signed hash as array of biginteger. Only return[0]
		/// contains a value: the signed hash.</returns>
		/// <remarks>No remarks</remarks>
		public override BigInteger[] Sign(BigInteger biHash, SecretKeyPacket skpKey, string strPassphrase) {
			//Signing and encrypting is just the same
			BigInteger[] biHashArray = {biHash};
			BigInteger biSignature = Decrypt(biHashArray, skpKey, strPassphrase);
			BigInteger[] biReturn = new BigInteger[1];
			
			biReturn[0] = biSignature;
			return biReturn;
		}
		
		/// <summary>
		/// Public key operation. Verifies biSignature with the keydata
		/// in the given public key packet and returns true if the signature
		/// is valid.
		/// </summary>
		/// <param name="biSignature">The signature that is about to
		/// be verified</param>
		/// <param name="biHash">The hash value of the signed message.</param>
		/// <param name="pkpKey">The public key packet with the key
		/// material for the verification.</param>
		/// <returns>True if the signature is valid, otherwise 
		/// false</returns>
		/// <remarks>No remarks</remarks>
		public override bool Verify(BigInteger[] biSignature, BigInteger biHash, PublicKeyPacket pkpKey) {
			RSA_Public_Key rpkKey = new RSA_Public_Key();
			
			if ((pkpKey.Algorithm != AsymAlgorithms.RSA_Encrypt_Sign) &&
			    	(pkpKey.Algorithm != AsymAlgorithms.RSA_Sign_Only)) {
				throw new System.ArgumentException("This public key is not supposed to be used for RSA signatures.");
			}
			if (pkpKey.KeyMaterial.Length != 2) {
				throw new System.ArgumentException("This is not a valid RSA Key");
			}
			
			rpkKey.n = pkpKey.KeyMaterial[0];
			rpkKey.e = pkpKey.KeyMaterial[1];
			
			BigInteger biReturn = Encrypt(biSignature[0], rpkKey)[0];
			
			return biReturn == biHash;
		}
		
	}
}

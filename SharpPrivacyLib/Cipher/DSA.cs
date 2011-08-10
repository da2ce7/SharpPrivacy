//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// DSA.cs: 
// 	Class for encrypting, decrypting, signing and verifying
//	using the DSA cipher.
//
// Parts of this code rely on portions of the go-mono implemenation
// of the cipher. These parts are copyright of their respective
// owners.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 07.01.2003: Created this file.
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
	/// The DSA class is there for signing and verifying messages
	/// with the DSA signature standard.
	/// </summary>
	/// <remarks>No remarks</remarks>
	public class DSA : AsymmetricCipher {

		private struct DSA_Public_Key {
			public BigInteger p;	    // prime 
			public BigInteger q;	    // group order 
			public BigInteger g;	    // group generator 
			public BigInteger y;	    // g^x mod p 
		}
		
		private struct DSA_Secret_Key {
			public BigInteger p;	    // prime 
			public BigInteger q;	    // group order 
			public BigInteger g;	    // group generator 
			public BigInteger y;	    // g^x mod p 
			public BigInteger x;	    // secret exponent
		}
		
		private BigInteger[][] biGeneratedKey;
		public BigInteger[][] GetGeneratedKey() {
			return this.biGeneratedKey;
		}

		
		/// <summary>
		/// Creates a new DES secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.
		/// </summary>
		/// <remarks>
		/// Creates a new DSA secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is p, q, g, y
		/// The order of the secret components is x.
		/// </remarks>
		/// <param name="nbits">The size of the key in bits.</param>
		/// <returns> a new DSA secret key and returns it as a
		/// 2 dimensional array of biginteger. return[0] holds
		/// the public values of the key and return[1] all the
		/// secret values.<br></br>
		/// The order of the public components is p, q, g, y
		/// The order of the secret components is x.</returns>
		public override BigInteger[][] Generate(int keyLength) {
			DSA_Secret_Key dskKey = new DSA_Secret_Key();
			dskKey = GenerateParams(keyLength);
			dskKey = GenerateKeyPair(dskKey);
			
			biGeneratedKey = new BigInteger[2][];
			
			biGeneratedKey[0] = new BigInteger[4];
			biGeneratedKey[0][0] = dskKey.p;
			biGeneratedKey[0][1] = dskKey.q;
			biGeneratedKey[0][2] = dskKey.g;
			biGeneratedKey[0][3] = dskKey.y;
			
			biGeneratedKey[1] = new BigInteger[1];
			biGeneratedKey[1][0] = dskKey.x;
			
			return biGeneratedKey;
		}
		
		/// <summary>
		/// Encryption is not supported for DSA. If you call this function,
		/// an Exception will be thrown.
		/// </summary>
		/// <remarks>
		/// Encryption is not supported for DSA. If you call this function,
		/// an Exception will be thrown.
		/// </remarks>
		public override BigInteger[] Encrypt(BigInteger biPlain, PublicKeyPacket pkpKey) {
			throw(new Exception("The DSA cipher cannot be used for encryption"));
		}
		
		/// <summary>
		/// Decryption is not supported for DSA. If you call this function,
		/// an Exception will be thrown.
		/// </summary>
		/// <remarks>
		/// Decryption is not supported for DSA. If you call this function,
		/// an Exception will be thrown.
		/// </remarks>
		public override BigInteger Decrypt(BigInteger[] biCipher, SecretKeyPacket spkKey, string strPassphrase) {
			throw(new Exception("The DSA cipher cannot be used for encryption/decryption"));
		}
		
		
		private BigInteger[,] ParseSecretKey(DSA_Secret_Key dskKey) {
			BigInteger[,] biReturn = new BigInteger[2,4];
			
			biReturn[0,0] = dskKey.p;
			biReturn[0,1] = dskKey.q;
			biReturn[0,2] = dskKey.g;
			biReturn[0,3] = dskKey.y;
			biReturn[1,0] = dskKey.x;
			
			return biReturn;
		}
		
		private bool CheckKey(DSA_Secret_Key dskKey) {
			// - p, q, g, x, y > 0
			if (dskKey.p <= 0 || dskKey.q <= 0 || dskKey.g <= 0 ||
			    dskKey.y <= 0 || dskKey.x <= 0) {
				return false;
			}
			
			// - p is odd, q is odd
			if (dskKey.p % 2 == 0 || dskKey.q % 2 == 0)
				return false;
			
			
			// - 2^159 < q < 2^160
			if (dskKey.q.bitCount() < 159)
				return false;
			
			// - 1 < g < p
			if (dskKey.g >= dskKey.p || dskKey.g <= 1) 
				return false;
			
			// - 1 < y < p
			if (dskKey.y >= dskKey.p || dskKey.y <= 1) 
				return false;
			
			// - x < q
			if (dskKey.x >= dskKey.q)
				return false;
			
			// - g^q mod p = 1
			if (dskKey.g.modPow(dskKey.q, dskKey.p) != 1)
				return false;
			
			// - g^x mod p = y
			if (dskKey.g.modPow(dskKey.x, dskKey.p) != dskKey.y)
				return false;
			
			return true;
			
		}
		
		private DSA_Secret_Key ParseSecretKey(SecretKeyPacket skpKey, string strPassphrase) {
			DSA_Secret_Key dskKey = new DSA_Secret_Key();
			
			dskKey.p = skpKey.PublicKey.KeyMaterial[0];
			dskKey.q = skpKey.PublicKey.KeyMaterial[1];
			dskKey.g = skpKey.PublicKey.KeyMaterial[2];
			dskKey.y = skpKey.PublicKey.KeyMaterial[3];

			BigInteger[] biSecretKeyMaterial = skpKey.GetDecryptedKeyMaterial(strPassphrase);
			
			dskKey.x = biSecretKeyMaterial[0];
			
			return dskKey;
			
		}
		
		private DSA_Public_Key ParsePublicKey(PublicKeyPacket pkpKey) {
			DSA_Public_Key dpkKey = new DSA_Public_Key();
			
			if (pkpKey.Algorithm != AsymAlgorithms.DSA)
				throw(new System.ArgumentException("The given key is not supposed to be used with DSA!"));
			
			if (pkpKey.KeyMaterial.Length != 4)
				throw(new System.ArgumentException("The given key is not a valid key for DSA!"));
			
			dpkKey.p = pkpKey.KeyMaterial[0];
			dpkKey.q = pkpKey.KeyMaterial[1];
			dpkKey.g = pkpKey.KeyMaterial[2];
			dpkKey.y = pkpKey.KeyMaterial[3];
			
			return dpkKey;
		}
		
		private BigInteger[] ParsePublicKey(DSA_Public_Key dpkKey) {
			BigInteger[] biReturn = new BigInteger[4];
			
			biReturn[0] = dpkKey.p;
			biReturn[1] = dpkKey.q;
			biReturn[2] = dpkKey.g;
			biReturn[3] = dpkKey.y;
			
			return biReturn;
		}
	
		// this part is quite fast
		private DSA_Secret_Key GenerateKeyPair(DSA_Secret_Key dskKey) {
			dskKey.x = new BigInteger();
			do {
				// size of x (private key) isn't affected by the keysize (512-1024)
				dskKey.x = BigInteger.genRandom(160);
				BigInteger xx = new BigInteger();
			} while ((dskKey.x == 0) || (dskKey.x >= dskKey.q));
	
			// calculate the public key y = g^x % p
			dskKey.y = dskKey.g.modPow(dskKey.x, dskKey.p);
			
			return dskKey;
		}
	
		private DSA_Secret_Key GenerateParams(int keyLength) {
			byte[] seed = new byte[20];
			byte[] part1 = new byte[20];
			byte[] part2 = new byte[20];
			byte[] u = new byte[20];
			RandomNumberGenerator rng = RandomNumberGenerator.Create();
			
			BigInteger p = new BigInteger();	    // prime 
			BigInteger q = new BigInteger();	    // group order 
			BigInteger g;	    // group generator 
			DSA_Secret_Key dskKey = new DSA_Secret_Key();
			
			SHA1 sha = SHA1.Create();
			
			int n = (keyLength - 1) / 160;
			byte[] w = new byte [keyLength / 8];
			bool primesFound = false;
			
			while (!primesFound) {
				do {
					rng.GetBytes(seed);
					part1 = sha.ComputeHash(seed);
					Array.Copy(seed, 0, part2, 0, seed.Length);
					
					add(part2, seed, 1);
					
					part2 = sha.ComputeHash(part2);
					
					for (int i = 0; i != u.Length; i++) 
						u[i] = (byte)(part1[i] ^ part2[i]);
					
					// first bit must be set (to respect key length)
					u[0] |= (byte)0x80;
					// last bit must be set (prime are all odds - except 2)
					u[19] |= (byte)0x01;
					
					q = new BigInteger(u);
				} while (!q.isProbablePrime());
				
				int counter = 0;
				int offset = 2;
				while (counter < 4096) {
					for (int k = 0; k < n; k++) {
						add(part1, seed, offset + k);
						part1 = sha.ComputeHash(part1);
						Array.Copy(part1, 0, w, w.Length - (k + 1) * part1.Length, part1.Length);
					}
	
					add(part1, seed, offset + n);
					part1 = sha.ComputeHash(part1);
					Array.Copy(part1, part1.Length - ((w.Length - (n) * part1.Length)), w, 0, w.Length - n * part1.Length);
	
					w[0] |= (byte)0x80;
					BigInteger xx = new BigInteger (w);
	
					BigInteger c = xx % (q * 2);
	
					p = xx - (c - 1);
	
					if (p.testBit((uint)(keyLength - 1))) {
						if (p.isProbablePrime()) {
							primesFound = true;
							break;
						}
					}
	
					counter += 1;
					offset += n + 1;
				}
				
			}
		
			// calculate the generator g
			BigInteger pMinusOneOverQ = (p - 1) / q;
			for (;;) {
				BigInteger h = new BigInteger();
				h = BigInteger.genRandom(keyLength);
				if ((h <= 1) || (h >= (p - 1)))
					continue;
	
				g = h.modPow(pMinusOneOverQ, p);
				if (g <= 1)
					continue;
				break;
			}
			
		    dskKey.p = p;
		    dskKey.q = q;
		    dskKey.g = g;
			
			return dskKey;
			
		}
		
		private void add(byte[] a, byte[] b, int value) {
			uint x = (uint)((b [b.Length - 1] & 0xff) + value);
	
			a[b.Length - 1] = (byte)x;
			x >>= 8;
	
			for (int i = b.Length - 2; i >= 0; i--) {
				x += (uint)(b[i] & 0xff);
				a[i] = (byte)x;
				x >>= 8;
			}
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
			if (biSignature == null)
				throw new ArgumentNullException("rgbSignature");
			
			DSA_Public_Key dpkKey = new DSA_Public_Key();
			dpkKey = ParsePublicKey(pkpKey);
			
			try {
				BigInteger m = biHash;
				BigInteger r = biSignature[0];
				BigInteger s = biSignature[1];
	
				if ((r < 0) || (dpkKey.q <= r))
					return false;
	
				if ((s < 0) || (dpkKey.q <= s))
					return false;
	
				BigInteger w = s.modInverse(dpkKey.q);
				BigInteger u1 = m * w % dpkKey.q;
				BigInteger u2 = r * w % dpkKey.q;
	
				u1 = dpkKey.g.modPow(u1, dpkKey.p);
				u2 = dpkKey.y.modPow(u2, dpkKey.p);
	
				BigInteger v = ((u1 * u2 % dpkKey.p) % dpkKey.q);
				return (v == r);
			} catch {
				throw new CryptographicException();
			}
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
		public override BigInteger[] Sign(BigInteger biHash, SecretKeyPacket skpKey, string strPassphase) {
			DSA_Secret_Key dskKey = new DSA_Secret_Key();
			
			dskKey = ParseSecretKey(skpKey, strPassphase);
			
			//check if the key has been mangled with
			if (!CheckKey(dskKey))
				throw(new Exception("This key does not fullfill the requirements of a valid DSA key. Please check if someone messed with your keys!"));
			
			//if (biHash == null)
			//	throw new ArgumentNullException();
			
			// (a) Select a random secret integer k; 0 < k < q.
			BigInteger k = new BigInteger();
			k = BigInteger.genRandom(160);
			while (k >= dskKey.q)
				k = BigInteger.genRandom(160);
			
			// (b) Compute r = ( k mod p) mod q
			BigInteger r = (dskKey.g.modPow (k, dskKey.p)) % dskKey.q;
			// (c) Compute k -1 mod q (e.g., using Algorithm 2.142).
			// (d) Compute s = k -1 fh(m) +arg mod q.
			BigInteger s = (k.modInverse (dskKey.q) * (biHash + dskKey.x * r)) % dskKey.q;
			
			BigInteger[] biReturn = new BigInteger[2];
			
			biReturn[0] = r;
			biReturn[1] = s;
			return biReturn;
		}
		
	
		
		
	}
}
		

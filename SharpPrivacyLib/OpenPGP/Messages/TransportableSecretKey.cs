//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// TransportableSecretKey.cs: 
// 	Class for handling secret keys in their transportable format.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 31.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP.Messages to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages
//
// (C) 2003, Daniel Fabian
//

/*
 * NOTE: The content of transportable secret keys is
 * not specified in RFC2440. We'll just use the same
 * format GnuPG uses.
 * 
 */

using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Collections;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// Transportable secret key contains a secret key in a format that
	/// can be transported from the local keyring to another computer or
	/// to a backup disk.
	/// </summary>
	/// <remarks>
	/// Transportable secret key contains a secret key in a format that
	/// can be transported from the local keyring to another computer or
	/// to a backup disk.
	/// </remarks>
	public class TransportableSecretKey {
		private SecretKeyPacket skpPrimaryKey;
		private ArrayList alUserIDs;
		private ArrayList alSubkeys;
		
		/// <summary>
		/// Creates a new transportable secret key with the properties
		/// of the base64 encoded transportable secret key given as
		/// argument.
		/// </summary>
		/// <param name="strBase64">An Base64 encoded transportable secret
		/// key.</param>
		/// <remarks>No remarks</remarks>
		public TransportableSecretKey(string strBase64) {
			alUserIDs = new ArrayList();
			alSubkeys = new ArrayList();
			
			this.Parse(strBase64);
		}
		
		/// <summary>
		/// Creates a new Transportable Secret key without any special
		/// preferences.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public TransportableSecretKey() {
			alUserIDs = new ArrayList();
			alSubkeys = new ArrayList();
		}
		
		/// <summary>
		/// Gets or sets the primary secret key of the transportable
		/// secret key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>The primary secret key of the transportable
		/// secret key.</value>
		public SecretKeyPacket PrimaryKey {
			get {
				return skpPrimaryKey;
			}
			set {
				skpPrimaryKey = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an arraylist containing userID packets with the
		/// userid's assigned to the secret key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An arraylist containing userID packets with the
		/// userid's assigned to the secret key.</value>
		public ArrayList UserIDs {
			get {
				return alUserIDs;
			}
			set {
				alUserIDs = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an arraylist containing secret subkey packets.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An arraylist containing secret subkey packets.</value>
		public ArrayList SubKeys {
			get {
				return alSubkeys;
			}
			set {
				alSubkeys = value;
			}
		}
		
		
		/// <summary>
		/// Returns a string representation of the transportable secret key.
		/// </summary>
		/// <returns>A string representation of the transportable secret 
		/// key.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strSize = PrimaryKey.PublicKey.KeyMaterial[0].bitCount().ToString();
			string strUserID = ((UserIDPacket)UserIDs.ToArray()[0]).UserID;
			
			string strReturn = strUserID + ": 0x" + PrimaryKey.PublicKey.KeyID.ToString("x") + " (" + strSize + ")";
			return strReturn;
		}
		
		/// <summary>
		/// Finds a subkey (or the primary key) with the given keyid
		/// and returns it. Returns null if the the fitting key has
		/// not been found.
		/// </summary>
		/// <remarks>No remarks.</remarks>
		/// <param name="lKeyID">The keyid to be sought in the transportable
		/// secret key.</param>
		/// <returns>The subkey (or the primary key) with the given keyid.
		/// Null if the the fitting key has not been found.</returns>
		public SecretKeyPacket FindKey(ulong lKeyID) {
			
			if (skpPrimaryKey.PublicKey.KeyID == lKeyID)
				return skpPrimaryKey;
			
			IEnumerator ieSubkeys = alSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				SecretKeyPacket skpKey = (SecretKeyPacket)ieSubkeys.Current;
				
				if (skpKey.PublicKey.KeyID == lKeyID)
					return skpKey;
			}
			
			return null;
		}
		
		/// <summary>
		/// Finds a subkey (or the primary key) that fits to the given 
		/// requirements (meaning it must be supposed to be used for 
		/// the given action, which can be either signing or encryption).
		/// If more than just one keys fullfill the requirements, the one
		/// with the newer creationdate is used.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <param name="aaAction">The action (signing or encrypting) for
		/// which the key should be used</param>
		/// <returns>Returns a public key packet fullfilling the given
		/// requirements (the action) or null, if it did not find such
		/// a key.</returns>
		public SecretKeyPacket FindKey(AsymActions aaAction) {
			DateTime dtCandidateTime = DateTime.Now;
			SecretKeyPacket skpCandidate = new SecretKeyPacket();
			bool bFound = false;
			
			// First check the primary Key
			if (aaAction == AsymActions.Encrypt) {
				if (skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
					
					dtCandidateTime = skpPrimaryKey.PublicKey.TimeCreated;
					bFound = true;
					skpCandidate = skpPrimaryKey;
				}
			} else if (aaAction == AsymActions.Sign) {
				if (skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.DSA ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Sign_Only ||
				    skpPrimaryKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
					
					dtCandidateTime = skpPrimaryKey.PublicKey.TimeCreated;
					bFound = true;
					skpCandidate = skpPrimaryKey;
				}
			}
			
			// Now check the subkeys
			IEnumerator ieSubkeys = alSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				SecretKeyPacket skpKey = (SecretKeyPacket)ieSubkeys.Current;
				if (aaAction == AsymActions.Encrypt) {
					
					if (skpKey.PublicKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
						
						if ((bFound && dtCandidateTime < skpKey.PublicKey.TimeCreated) || (!bFound)) {
							dtCandidateTime = skpKey.PublicKey.TimeCreated;
							bFound = true;
							skpCandidate = skpKey;
						}
					}
				} else if (aaAction == AsymActions.Sign) {
					if (skpKey.PublicKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.DSA ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Sign_Only ||
					    skpKey.PublicKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
						
						if ((bFound && dtCandidateTime < skpKey.PublicKey.TimeCreated) || (!bFound)) {
							dtCandidateTime = skpKey.PublicKey.TimeCreated;
							bFound = true;
							skpCandidate = skpKey;
						}
					}
				}
				
			}
			
			if (bFound)
				return skpCandidate;
			
			return null;
		}
		
		
		
		/// <summary>
		/// Generates the transportable secret key out of the properties
		/// in this.
		/// </summary>
		/// <returns>Returns a byte array containing the openpgp encoded
		/// representation of the transportable secret key.</returns>
		/// <remarks>
		/// Generates the transportable secret key out of the properties
		/// in this.
		/// </remarks>
		public byte[] Generate() {
			
			if (alUserIDs.Count == 0)
				throw new Exception("A transportable secret key must have at least one userid assigned to the primary key!");
			
			byte[] bSecretKey = skpPrimaryKey.Generate();
			byte[] bUserIDs = new byte[0];
			byte[] bSubkeys = new byte[0];
			
			IEnumerator ieUserIDs = alUserIDs.GetEnumerator();
			while (ieUserIDs.MoveNext()) {
				if (!(ieUserIDs.Current is UserIDPacket))
					continue;
				
				UserIDPacket uipID = (UserIDPacket)ieUserIDs.Current;
				byte[] bUserID = uipID.Generate();
				byte[] bOldUserIDs = new byte[bUserIDs.Length];
				bUserIDs.CopyTo(bOldUserIDs, 0);
				bUserIDs = new byte[bOldUserIDs.Length + bUserID.Length];
				
				bOldUserIDs.CopyTo(bUserIDs, 0);
				bUserID.CopyTo(bUserIDs, bOldUserIDs.Length);
			}
			
			IEnumerator ieSubkeys = alSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (!(ieSubkeys.Current is SecretKeyPacket))
					continue;
				
				SecretKeyPacket skpSubkey = (SecretKeyPacket)ieSubkeys.Current;
				byte[] bSubkey = skpSubkey.Generate();
				byte[] bOldSubkeys = new byte[bSubkeys.Length];
				bSubkeys.CopyTo(bOldSubkeys, 0);
				bSubkeys = new byte[bOldSubkeys.Length + bSubkey.Length];
				
				bOldSubkeys.CopyTo(bSubkeys, 0);
				bSubkey.CopyTo(bSubkeys, bOldSubkeys.Length);
			}
			
			byte[] bReturn = new byte[bSecretKey.Length + bUserIDs.Length + bSubkeys.Length];
			bSecretKey.CopyTo(bReturn, 0);
			bUserIDs.CopyTo(bReturn, bSecretKey.Length);
			bSubkeys.CopyTo(bReturn, bSecretKey.Length + bUserIDs.Length);
			
			return bReturn;
		}
		

		/// <summary>
		/// Parses the radix64 encoded representation of a transportable secret
		/// key given as an argument to populate the parameters of this.
		/// </summary>
		/// <param name="strRadix64">Radix64 representation of an transportable
		/// secret key</param>
		/// <exception cref="System.ArgumentException">Throws an 
		/// ArgumentException if the radix64 string given as a parameter is
		/// not an transportable secret key.</exception>
		/// <remarks>No remarks</remarks>
		public void Parse(string strRadix64) {
			Packet[] pPackets = Packet.ParsePackets(strRadix64);
			
			int nCurrentPacket = 0;
			int nUserIDCounter = 0;
			
			try {
				// First we expect a PublicKeyPacket
				if (!(pPackets[0] is SecretKeyPacket)) {
					throw(new ArgumentException("The given packet is not in the required transportable secret key format!"));
				}
				this.PrimaryKey = (SecretKeyPacket)pPackets[nCurrentPacket++];
				
				// Next we expect one or more userid packets
				while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is UserIDPacket)) {
					UserIDPacket uipUserID = (UserIDPacket)pPackets[nCurrentPacket++];
					this.UserIDs.Add(uipUserID);
					nUserIDCounter++;
				}
				
				// we want at least 1 userid packet.
				if (nUserIDCounter == 0) {
					throw(new ArgumentException("The given packet is not in the required transportable secret key format!"));
				}
				
				// Finally we have zero or more subkeys
				while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is SecretKeyPacket)) {
					SecretKeyPacket skpSubKey = (SecretKeyPacket)pPackets[nCurrentPacket++];
					this.SubKeys.Add(skpSubKey);
				}
			} catch (System.IndexOutOfRangeException) {
				if (nUserIDCounter == 0) {
					throw(new ArgumentException("The given packet is not in the required transportable secret key format!"));
				}
			}
			
			
		}
		
		/// <summary>
		/// Returns true if the given object is the "this" key.
		/// </summary>
		/// <remarks>
		/// The keys are compared by there fingerprint. If the fingerprint
		/// is the same, the keys are said to be the same.
		/// </remarks>
		/// <param name="o">An object that shall be compared against 
		/// this.</param>
		/// <returns>True if the giben object o is the same as the
		/// "this" key.</returns>
		public override bool Equals(object o) {
			if (o is TransportableSecretKey) {
				TransportableSecretKey tskKey = (TransportableSecretKey)o;
				return (tskKey.PrimaryKey.PublicKey.Fingerprint == this.PrimaryKey.PublicKey.Fingerprint);
			}
			return false;
		}
		
		public override int GetHashCode() {
			return (int)(this.PrimaryKey.PublicKey.KeyID & 0xFFFFFFFF);
		}

		public static TransportableSecretKey[] SplitKeys(string strRadix64) {
			ArrayList alKeys = new ArrayList();
			Packet[] pPackets = Packet.ParsePackets(strRadix64);
			
			byte[] bOneKey = new byte[0];
			for (int i=0; i<pPackets.Length; i++) {
				if (pPackets[i] is SecretKeyPacket) {
					SecretKeyPacket skpKey = (SecretKeyPacket)pPackets[i];
					if ((skpKey.Content == ContentTypes.SecretKey) && (bOneKey.Length > 10)) {
						TransportableSecretKey tskKey = new TransportableSecretKey(Radix64.Encode(bOneKey, true));
						alKeys.Add(tskKey);
						bOneKey = new byte[0];
					}
				}
				byte[] bPacket = pPackets[i].Generate();
				byte[] bTmpKey = new byte[bOneKey.Length];
				bOneKey.CopyTo(bTmpKey, 0);
				bOneKey = new byte[bOneKey.Length + bPacket.Length];
				Array.Copy(bTmpKey, 0, bOneKey, 0, bTmpKey.Length);
				Array.Copy(bPacket, 0, bOneKey, bTmpKey.Length, bPacket.Length);
			}
			
			if (bOneKey.Length > 10) {
				TransportableSecretKey tskKey = new TransportableSecretKey(Radix64.Encode(bOneKey, true));
				alKeys.Add(tskKey);
			}
			
			TransportableSecretKey[] tskKeys = new TransportableSecretKey[alKeys.Count];
			int iCount = 0;
			IEnumerator ieKeys = alKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportableSecretKey))
					continue;
				
				tskKeys[iCount++] = (TransportableSecretKey)ieKeys.Current;
				
			}
			
			return tskKeys;
		}		
	}
}

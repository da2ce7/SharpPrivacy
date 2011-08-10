//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// TransportablePublicKey.cs: 
// 	Class for handling public keys in their transportable format.
//
// Author(s):
//	Daniel Fabian (df@sharpprivacy.net)
//  Roberto Rossi
//
//
// Version: 0.2.0
//
// Changelog:
//	- 23.02.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP.Messages to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages
//  - 28.02.2004: Several bugfixes by Roberto Rossi
//
// (C) 2003 - 2004, Daniel Fabian, Roberto Rossi
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Collections;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// Transportable Public Key is an OpenPGP message as specified in
	/// RFC2440. It contains a user's public key, its subkeys, any user
	/// ids as well as certifications (signatures).
	/// </summary>
	/// <remarks>
	/// Transportable Public Key is an OpenPGP message as specified in
	/// RFC2440. It contains a user's public key, its subkeys, any user
	/// ids as well as certifications (signatures).
	/// </remarks>
	public class TransportablePublicKey {
		private PublicKeyPacket pkpPrimaryKey;
		private ArrayList alRevocationSignatures;
		private ArrayList alRevocationKeys;
		private ArrayList alCertifications;
		private ArrayList alSubkeys;
		private string strPrimaryUserID;
		
		/// <summary>
		/// Creates a new Transportable secret key with the
		/// parameters of the base64 encoded key given as
		/// argument.
		/// </summary>
		/// <param name="strBase64">A transportable public key
		/// encoded in base64.</param>
		/// <remarks>No remarks</remarks>
		public TransportablePublicKey(string strBase64) {
			alRevocationSignatures = new ArrayList();
			alCertifications = new ArrayList();
			alRevocationKeys = new ArrayList();
			alSubkeys = new ArrayList();
			strPrimaryUserID = "";
			this.Parse(strBase64);
		}

		/// <summary>
		/// Creates a new Transportable public key. No special
		/// preferences are choses.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public TransportablePublicKey() {
			alRevocationSignatures = new ArrayList();
			alCertifications = new ArrayList();
			alRevocationKeys = new ArrayList();
			alSubkeys = new ArrayList();
			strPrimaryUserID = "";
		}
		
		/// <summary>
		/// Readonly. Returns the primary user id of the transportable
		/// public key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// Readonly. Returns the primary user id of the transportable
		/// public key.
		/// </value>
		public string PrimaryUserID {
			get {
				if (strPrimaryUserID.Length == 0)
					strPrimaryUserID = FindPrimaryUserID();
				
				return strPrimaryUserID;
			}
		}
		
		public CertifiedUserID PrimaryUserIDCert {
			get {
				foreach(CertifiedUserID cuid in this.Certifications) {
					if(cuid.UserID.UserID==this.PrimaryUserID)
						return cuid;
				}
				throw new Exception("Primary UID certificate not found");
			}
		}
		
		public DateTime KeyExpirationTime {
			get {
				DateTime dtExpiration = this.FindExpirationDate();
				return new DateTime(this.PrimaryKey.TimeCreated.Ticks + (dtExpiration.Ticks - new DateTime(1970, 1, 1).Ticks));
			}
		}
		/// <summary>
		/// Gets or sets the primary key of the transportable public key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// Gets or sets the primary key of the transportable public key.
		/// </value>
		public PublicKeyPacket PrimaryKey {
			get {
				return pkpPrimaryKey;
			}
			set {
				pkpPrimaryKey = value;
			}
		}
		
		/// <summary>
		/// An arraylist containing revocation signatures for the key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// An arraylist containing revocation signatures for the key.
		/// </value>
		public ArrayList RevocationSignatures {
			get {
				return alRevocationSignatures;
			}
			set {
				alRevocationSignatures = value;
			}
		}
		
		public ArrayList RevocationKeys {
			get {
				return alRevocationKeys;
			}
			set {
				alRevocationKeys = value;
			}
		}
		
		/// <summary>
		/// An Arraylist containing certifications (trust signatures)
		/// for the key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// An Arraylist containing certifications (trust signatures)
		/// for the key.
		/// </value>
		public ArrayList Certifications {
			get {
				return alCertifications;
			}
			set {
				alCertifications = value;
			}
		}
		
		/// <summary>
		/// An arraylist containing all the subkeys belonging to the
		/// key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>
		/// An arraylist containing all the subkeys belonging to the
		/// key.
		/// </value>
		public ArrayList SubKeys {
			get {
				return alSubkeys;
			}
			set {
				alSubkeys = value;
			}
		}
		
		/// <summary>
		/// Returns a string representation of the transportable public key.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <returns>Returns a string representation of the transportable
		/// public key.</returns>
		public override string ToString() {
			string strReturn = "";
			
			strReturn += "Abstract:\r\n";
			strReturn += "Number of Certificates: " + this.Certifications.Count + "\r\n";
			
			
			strReturn += "\r\n\r\n\r\nPublic Key Packet: \r\n";
			strReturn += this.PrimaryKey.ToString() + "\r\n\r\n";
			
			IEnumerator ieLoop = this.Certifications.GetEnumerator();
			while (ieLoop.MoveNext()) {
				if (ieLoop.Current is CertifiedUserID) {
					CertifiedUserID cuiUserID = (CertifiedUserID)ieLoop.Current;
					strReturn += cuiUserID.ToString();
				}
			}
			
			return strReturn;
		}
		
		/// <summary>
		/// Generates the transportable public key out of the properties
		/// in this.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <returns>Returns a byte array containing the openpgp encoded
		/// representation of the transportable public key.</returns>
		public byte[] Generate() {
			byte[] bPrimaryKey = this.PrimaryKey.Generate();
			
			//Revocation signatures
			int iLength = 0;
			IEnumerator ieRevocations = this.RevocationSignatures.GetEnumerator();
			while (ieRevocations.MoveNext()) {
				if (ieRevocations.Current is SignaturePacket) {
					iLength += ((SignaturePacket)ieRevocations.Current).Generate().Length;
				}
			}
			byte[] bRevocations = new byte[iLength];
			ieRevocations = this.RevocationSignatures.GetEnumerator();
			int iPosition = 0;
			while (ieRevocations.MoveNext()) {
				if (ieRevocations.Current is SignaturePacket) {
					byte[] bRev = ((SignaturePacket)ieRevocations.Current).Generate();
					Array.Copy(bRev, 0, bRevocations, iPosition, bRev.Length);
					iPosition += bRev.Length;
				}
			}

			// Revoker keys
			iLength = 0;
			IEnumerator ieRevoker = this.RevocationKeys.GetEnumerator();
			while (ieRevoker.MoveNext()) {
				if (ieRevoker.Current is SignaturePacket) 
					iLength += ((SignaturePacket)ieRevoker.Current).Generate().Length;
			}
			
			byte[] bRevoker = new byte[iLength];
			ieRevoker = this.RevocationKeys.GetEnumerator();
			iPosition = 0;
			while (ieRevoker.MoveNext()) {
				if (ieRevoker.Current is SignaturePacket) {
					byte[] bRev = ((SignaturePacket)ieRevoker.Current).Generate();
					Array.Copy(bRev, 0, bRevoker, iPosition, bRev.Length);
					iPosition += bRev.Length;
				}
			}
						
			//Certificates
			iLength = 0;
			IEnumerator ieCertificates = this.Certifications.GetEnumerator();
			while (ieCertificates.MoveNext()) {
				if (ieCertificates.Current is CertifiedUserID) {
					CertifiedUserID cuiID = (CertifiedUserID)ieCertificates.Current;
					iLength += cuiID.Generate().Length;
				}
			}
			byte[] bCertificates = new byte[iLength];
			iPosition = 0;
			ieCertificates = this.Certifications.GetEnumerator();
			while (ieCertificates.MoveNext()) {
				if (ieCertificates.Current is CertifiedUserID) {
					CertifiedUserID cuiID = (CertifiedUserID)ieCertificates.Current;
					byte[] bCert = cuiID.Generate();
					Array.Copy(bCert, 0, bCertificates, iPosition, bCert.Length);
					iPosition += bCert.Length;
				}
			}
			
			//SubKeys
			iLength = 0;
			IEnumerator ieSubkeys = this.SubKeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (ieSubkeys.Current is CertifiedPublicSubkey) {
					CertifiedPublicSubkey cpsKey = (CertifiedPublicSubkey)ieSubkeys.Current;
					iLength += cpsKey.Generate().Length;
				}
			}
			byte[] bSubkeys = new byte[iLength];
			iPosition = 0;
			ieSubkeys = this.SubKeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				if (ieSubkeys.Current is CertifiedPublicSubkey) {
					CertifiedPublicSubkey cpsKey = (CertifiedPublicSubkey)ieSubkeys.Current;
					byte[] bKey = cpsKey.Generate();
					Array.Copy(bKey, 0, bSubkeys, iPosition, bKey.Length);
					iPosition += bKey.Length;
				}
			}
			
			byte[] bData = new byte[bPrimaryKey.Length + bRevocations.Length + 
									bRevoker.Length + bCertificates.Length + bSubkeys.Length];
			iPosition = 0;
			Array.Copy(bPrimaryKey, bData, bPrimaryKey.Length);
			iPosition = bPrimaryKey.Length;
			Array.Copy(bRevocations, 0, bData, iPosition, bRevocations.Length);
			iPosition += bRevocations.Length;
			Array.Copy(bRevoker, 0, bData, iPosition, bRevoker.Length);
			iPosition += bRevoker.Length;
			Array.Copy(bCertificates, 0, bData, iPosition, bCertificates.Length);
			iPosition += bCertificates.Length;
			Array.Copy(bSubkeys, 0, bData, iPosition, bSubkeys.Length);
			
			return bData;
			
		}
		
		/// <summary>
		/// Finds a subkey (or the primary key) with the given keyid
		/// and returns it. Returns null if the the fitting key has
		/// not been found.
		/// </summary>
		/// <remarks>If the public key has been revoked, it is ignored
		/// and NOT found by this function!!!</remarks>
		/// <param name="lKeyID">The keyid to be sought in the transportable
		/// public key.</param>
		/// <returns>The subkey (or the primary key) with the given keyid.
		/// Null if the the fitting key has not been found.</returns>
		public PublicKeyPacket FindKey(ulong lKeyID) {
			
			if (pkpPrimaryKey.KeyID == lKeyID)
				return pkpPrimaryKey;
			
			IEnumerator ieSubkeys = alSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				CertifiedPublicSubkey cpsKey = (CertifiedPublicSubkey)ieSubkeys.Current;
				
				// The subkey has been revoced
				if (cpsKey.RevocationSignature != null) 
					continue;
				
				PublicKeyPacket pkpKey = cpsKey.Subkey;
				if (pkpKey.KeyID == lKeyID)
					return pkpKey;
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
		public PublicKeyPacket FindKey(AsymActions aaAction) {
			DateTime dtCandidateTime = DateTime.Now;
			PublicKeyPacket pkpCandidate = new PublicKeyPacket();
			bool bFound = false;
			
			// First check the primary Key
			if (aaAction == AsymActions.Encrypt) {
				if (pkpPrimaryKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
					
					dtCandidateTime = pkpPrimaryKey.TimeCreated;
					bFound = true;
					pkpCandidate = pkpPrimaryKey;
				}
			} else if (aaAction == AsymActions.Sign) {
				if (pkpPrimaryKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.DSA ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.RSA_Sign_Only ||
				    pkpPrimaryKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
					
					dtCandidateTime = pkpPrimaryKey.TimeCreated;
					bFound = true;
					pkpCandidate = pkpPrimaryKey;
				}
			}
			
			// Now check the subkeys
			IEnumerator ieSubkeys = alSubkeys.GetEnumerator();
			while (ieSubkeys.MoveNext()) {
				CertifiedPublicSubkey cpsKey = (CertifiedPublicSubkey)ieSubkeys.Current;
				
				// The subkey has been revoced
				if (cpsKey.RevocationSignature != null) 
					continue;
				
				PublicKeyPacket pkpKey = cpsKey.Subkey;
				if (aaAction == AsymActions.Encrypt) {
					
					if (pkpKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
					    pkpKey.Algorithm == AsymAlgorithms.ElGamal_Encrypt_Only ||
					    pkpKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Only ||
					    pkpKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
						
						if ((bFound && dtCandidateTime < pkpKey.TimeCreated) || (!bFound)) {
							dtCandidateTime = pkpKey.TimeCreated;
							bFound = true;
							pkpCandidate = pkpKey;
						}
					}
				} else if (aaAction == AsymActions.Sign) {
					if (pkpKey.Algorithm == AsymAlgorithms.ElGama_Encrypt_Sign ||
					    pkpKey.Algorithm == AsymAlgorithms.DSA ||
					    pkpKey.Algorithm == AsymAlgorithms.RSA_Sign_Only ||
					    pkpKey.Algorithm == AsymAlgorithms.RSA_Encrypt_Sign) {
						
						if ((bFound && dtCandidateTime < pkpKey.TimeCreated) || (!bFound)) {
							dtCandidateTime = pkpKey.TimeCreated;
							bFound = true;
							pkpCandidate = pkpKey;
						}
					}
				}
				
			}
			
			if (bFound)
				return pkpCandidate;
			
			return null;
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
			if (o is TransportablePublicKey) {
				TransportablePublicKey tpkKey = (TransportablePublicKey)o;
				return (tpkKey.PrimaryKey.Fingerprint == this.PrimaryKey.Fingerprint);
			}
			return false;
		}
		
		public override int GetHashCode() {
			return (int)(this.PrimaryKey.KeyID & 0xFFFFFFFF);
		}
		
		
		/// <summary>
		/// Parses the radix64 encoded representation of a transportable public
		/// key given as an argument to populate the parameters of this.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <param name="strRadix64">Radix64 representation of an transportable
		/// public key</param>
		/// <exception cref="System.ArgumentException">Throws an 
		/// ArgumentException if the radix64 string given as a parameter is
		/// not an transportable public key.</exception>
		public void Parse(string strRadix64) {
			Packet[] pPackets = Packet.ParsePackets(strRadix64);
			
			int nCurrentPacket = 0;
			int nUserIDCounter = 0;
			
			try {
				// First we expect a PublicKeyPacket
				if (!(pPackets[0] is PublicKeyPacket))
					throw(new ArgumentException("The given packet is not in the required transportable public key format (packet 0 should have been public key packet)!"));
				
				this.PrimaryKey = (PublicKeyPacket)pPackets[nCurrentPacket++];
				
				// Next we expect zero or more revocation signatures
				while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is SignaturePacket)) {
					SignaturePacket spRevocation = (SignaturePacket)pPackets[nCurrentPacket++];
					if (spRevocation.SignatureType == SignatureTypes.KeyRevocationSignature) {
						this.RevocationSignatures.Add(spRevocation);
					} else if(spRevocation.SignatureType == SignatureTypes.KeySignature) {
						this.RevocationKeys.Add(spRevocation);
					} else
						throw(new ArgumentException("The given packet is not in the required transportable public key format (expected zero or more revocation signatures, was: " + spRevocation.SignatureType + ")!"));
				}
				
				// Next in queue must be one or more UserID Packets
				while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is UserIDPacket)) {
					nUserIDCounter++;
					CertifiedUserID cuiUserID = new CertifiedUserID();
					UserIDPacket uipUserID = (UserIDPacket)pPackets[nCurrentPacket++];
					cuiUserID.UserID = uipUserID;
					
					// For every UserIDPacket we expect zero or more Signatures (Certificates)
					while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is SignaturePacket)) {
						SignaturePacket spCertificate = (SignaturePacket)pPackets[nCurrentPacket++];
						if ((spCertificate.SignatureType != SignatureTypes.UserIDSignature) &&
						    (spCertificate.SignatureType != SignatureTypes.UserIDSignature_CasualVerification) &&
						    (spCertificate.SignatureType != SignatureTypes.UserIDSignature_NoVerification) &&
						    (spCertificate.SignatureType != SignatureTypes.UserIDSignature_PositivVerification) &&
							(spCertificate.SignatureType != SignatureTypes.CertificationRevocationSignature)) {
							throw(new ArgumentException("The given packet is not in the required transportable public key format (expected zero or more Signatures/Certificates)!"));
						}
						cuiUserID.Certificates.Add(spCertificate);
					}
					this.Certifications.Add(cuiUserID);
				}
				
				// There was no UserIDPacket. This is fatal!!!
				if (nUserIDCounter == 0) {
					throw(new ArgumentException("The given packet is not in the required transportable public key format (there was no UserIDPacket)!"));
				}
				
				// Finally we have zero or more subkeys
				while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is PublicKeyPacket)) {
					PublicKeyPacket pkpSubKey = (PublicKeyPacket)pPackets[nCurrentPacket++];
					CertifiedPublicSubkey cpsSubKey = new CertifiedPublicSubkey();
					cpsSubKey.Subkey = pkpSubKey;
					
					while ((nCurrentPacket < pPackets.Length) && (pPackets[nCurrentPacket] is SignaturePacket)) {
						SignaturePacket spKeySignature = (SignaturePacket)pPackets[nCurrentPacket++];
						if (spKeySignature.SignatureType == SignatureTypes.SubkeyBindingSignature) {
							cpsSubKey.KeyBindingSignature = spKeySignature;
						} else if (spKeySignature.SignatureType == SignatureTypes.SubkeyRevocationSignature) {
							cpsSubKey.RevocationSignature = spKeySignature;
						}
					} 
					if (nCurrentPacket < pPackets.Length) {
						if (!(pPackets[nCurrentPacket] is PublicKeyPacket)) {
							throw(new ArgumentException("The given packet is not in the required transportable public key format (expected public subkey packet)!"));
						}
					}
					/*
					if (nCurrentPacket < pPackets.Length) {
						if (pPackets[nCurrentPacket] is SignaturePacket) {
							SignaturePacket spSubkeyRev = (SignaturePacket)pPackets[nCurrentPacket++];
							cpsSubKey.RevocationSignature = spSubkeyRev;
						}
					}
					*/
					this.SubKeys.Add(cpsSubKey);
				}
			} catch (System.IndexOutOfRangeException) {
				if (nUserIDCounter == 0) {
					throw(new ArgumentException("The given packet is not in the required transportable public key format (no userid packet found)!"));
				}
			}
		}	
		
		private DateTime FindExpirationDate() {
			IEnumerator ieCertificates = this.alCertifications.GetEnumerator();
			while (ieCertificates.MoveNext()) {
				if (!(ieCertificates.Current is CertifiedUserID))
					continue;
				
				CertifiedUserID cuiID = (CertifiedUserID)ieCertificates.Current;
				IEnumerator ieSignatures = cuiID.Certificates.GetEnumerator();
				while (ieSignatures.MoveNext()) {
					if (!(ieSignatures.Current is SignaturePacket))
						continue;
					
					SignaturePacket spCertificate = (SignaturePacket)ieSignatures.Current;
					
					// look only at selfsignatures
					if (spCertificate.KeyID != this.PrimaryKey.KeyID)
						continue;
					
					for (int i=0; i<spCertificate.HashedSubPackets.Length; i++) {
						if (spCertificate.HashedSubPackets[i].Type == SignatureSubPacketTypes.KeyExpirationTime) {
							return spCertificate.HashedSubPackets[i].KeyExpirationTime;
						}
					}
				}
			}
			
			throw new Exception("never");
			
		}
		
		public SymAlgorithms[] FindPreferedAlgorithms() {
			IEnumerator ieCertificates = this.alCertifications.GetEnumerator();
			while (ieCertificates.MoveNext()) {
				if (!(ieCertificates.Current is CertifiedUserID))
					continue;
				
				CertifiedUserID cuiID = (CertifiedUserID)ieCertificates.Current;
				IEnumerator ieSignatures = cuiID.Certificates.GetEnumerator();
				while (ieSignatures.MoveNext()) {
					if (!(ieSignatures.Current is SignaturePacket))
						continue;
					
					SignaturePacket spCertificate = (SignaturePacket)ieSignatures.Current;
					
					// look only at selfsignatures
					if (spCertificate.KeyID != this.PrimaryKey.KeyID)
						continue;
					
					try {
						SymAlgorithms[] saReturn = spCertificate.FindPreferedSymAlgorithms();
						return saReturn;
					} catch (Exception) {}
					
				}
			}
			
			throw new Exception("none found!");
			
		}
		
		private string FindPrimaryUserID() {
			string strReturn = "";
			int nUserIDCounter = 0;
			IEnumerator ieCertificates = this.alCertifications.GetEnumerator();
			while (ieCertificates.MoveNext()) {
				if (!(ieCertificates.Current is CertifiedUserID))
					continue;
				
				nUserIDCounter++;
				CertifiedUserID cuiID = (CertifiedUserID)ieCertificates.Current;
				IEnumerator ieSignatures = cuiID.Certificates.GetEnumerator();
				while (ieSignatures.MoveNext()) {
					if (!(ieSignatures.Current is SignaturePacket))
						continue;
					
					SignaturePacket spCertificate = (SignaturePacket)ieSignatures.Current;
					
					// look only at selfsignatures
					if (spCertificate.KeyID != this.PrimaryKey.KeyID)
						continue;
					
					if (nUserIDCounter == 1) {
						strReturn = cuiID.UserID.UserID;
					}
					for (int i=0; i<spCertificate.UnhashedSubPackets.Length; i++) {
						if ((spCertificate.UnhashedSubPackets[i].Type == SignatureSubPacketTypes.PrimaryUserID)  && (spCertificate.UnhashedSubPackets[i].PrimaryUserID)) {
							strReturn = cuiID.UserID.UserID;
						}
					}
					for (int i=0; i<spCertificate.HashedSubPackets.Length; i++) {
						if ((spCertificate.HashedSubPackets[i].Type == SignatureSubPacketTypes.PrimaryUserID)  && (spCertificate.HashedSubPackets[i].PrimaryUserID)) {
							strReturn = cuiID.UserID.UserID;
						}
					}
				}
			}
			
			return strReturn;
		}
		
		public static TransportablePublicKey[] SplitKeys(string strRadix64) {
			ArrayList alKeys = new ArrayList();
			Packet[] pPackets = Packet.ParsePackets(strRadix64);
			
			byte[] bOneKey = new byte[0];
			for (int i=0; i<pPackets.Length; i++) {
				if (pPackets[i] is PublicKeyPacket) {
					PublicKeyPacket pkpKey = (PublicKeyPacket)pPackets[i];
					if ((pkpKey.Content == ContentTypes.PublicKey) && (bOneKey.Length > 10)) {
						TransportablePublicKey tpkKey = new TransportablePublicKey(Radix64.Encode(bOneKey, true));
						alKeys.Add(tpkKey);
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
				TransportablePublicKey tpkKey = new TransportablePublicKey(Radix64.Encode(bOneKey, true));
				alKeys.Add(tpkKey);
			}
			
			TransportablePublicKey[] tpkKeys = new TransportablePublicKey[alKeys.Count];
			int iCount = 0;
			IEnumerator ieKeys = alKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportablePublicKey))
					continue;
				
				tpkKeys[iCount++] = (TransportablePublicKey)ieKeys.Current;
				
			}
			
			return tpkKeys;
		}
		
	}
}

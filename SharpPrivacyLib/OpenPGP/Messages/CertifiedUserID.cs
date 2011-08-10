//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// CertifiedUserID.cs: 
// 	Class for handling Signatures on user ids.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 02.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP.Messages to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Collections;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// <para>CertifiedUserID is a submessage of TransportablePublicKey
	/// and consists out of a user ID for a key and zero or more
	/// certifications (signatures) for the key.</para>
	/// <para>In general a userid should always have at least one signature,
	/// a keybinding signature by the according secret key.</para>
	/// </summary>
	/// <remarks>
	/// <para>CertifiedUserID is a submessage of TransportablePublicKey
	/// and consists out of a user ID for a key and zero or more
	/// certifications (signatures) for the key.</para>
	/// <para>In general a userid should always have at least one signature,
	/// a keybinding signature by the according secret key.</para>
	/// </remarks>
	public class CertifiedUserID {
		
		/// <summary>
		/// Represents the validity status of a certification.
		/// </summary>
		/// <remarks>
		/// Represents the validity status of a certification.
		/// </remarks>
		public enum ValidityStatus {
			
			/// <summary>
			/// Signature did not verify correctly
			/// </summary>
			/// <remarks>No remarks</remarks>
			Invalid = 0,
			
			/// <summary>
			/// Signature verified corretly
			/// </summary>
			/// <remarks>No remarks</remarks>
			Valid = 1,
			
			/// <summary>
			/// Signature has not yet been verified
			/// </summary>
			/// <remarks>No remarks</remarks>
			NotYetValidated = 2,
			
			/// <summary>
			/// Signature cannot be verified as the neccessary
			/// public key is not available (in the keyring)
			/// </summary>
			/// <remarks>No remarks</remarks>
			ValidationKeyUnavailable = 3
		}
		
		private UserIDPacket uipUserID;
		private ArrayList alCertificates;
		private ValidityStatus validitystatus;

		public ValidityStatus CertificationValidityStatus {
			get {
				return this.validitystatus;
			}
		}
		
		/// <summary>
		/// Creates a new CertifiedUserID
		/// </summary>
		/// <remarks>No remarks</remarks>
		public CertifiedUserID() {
			alCertificates = new ArrayList();
			this.validitystatus =  ValidityStatus.NotYetValidated;
		}
		
		/// <summary>
		/// Gets or sets an OpenPGP UserIDPacket. This packet
		/// makes up the userid for which the signatures are there.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An OpenPGP UserIDPacket. This packet makes up 
		/// the userid for which the signatures are there.</value>
		public UserIDPacket UserID {
			get {
				return uipUserID;
			}
			set {
				uipUserID = value;
			}
		}
		
		/// <summary>
		/// Gets or sets an arraylist containing certificats (signatures)
		/// that make the according userid trustworthy.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An arraylist containing certificats 
		/// (signatures) that make the according userid trustworthy.</value>
		public ArrayList Certificates {
			get {
				return alCertificates;
			}
			set {
				alCertificates = value;
			}
		}
		
		/// <summary>
		/// Validates all certificates belonging the the given public key packet
		/// and the current certifications.
		/// </summary>
		/// <remarks>
		/// So far only works with v4 signatures!
		/// </remarks>
		/// <param name="pkpKey">The public key packet to which the userid
		/// belongs.</param>
		/// <param name="pkrRing">A keyring containing all public keys known to
		/// the system. This is neccessary in order to verify the signatures.
		/// </param>
		public void Validate(PublicKeyPacket pkpKey, PublicKeyRing pkrRing) {
			IEnumerator ieCertificates = Certificates.GetEnumerator();
			this.validitystatus = ValidityStatus.Valid;
			while (ieCertificates.MoveNext()) {
				if (ieCertificates.Current is SignaturePacket) {
					SignaturePacket spCert = (SignaturePacket)ieCertificates.Current;
					
					TransportablePublicKey tkpSigningKey = pkrRing.Find(spCert.KeyID, true);
					if (tkpSigningKey == null) {
						this.validitystatus = ValidityStatus.ValidationKeyUnavailable;
						continue;
					}
					PublicKeyPacket pkpSigningKey = tkpSigningKey.PrimaryKey;
					
					if (spCert.Version == SignaturePacketVersionNumbers.v4) {
						byte[] bKey = new byte[pkpKey.Body.Length + 3];
						bKey[0] = 0x99;
						bKey[1] = (byte)((pkpKey.Body.Length >> 8) & 0xFF);
						bKey[2] = (byte)(pkpKey.Body.Length & 0xFF);
						Array.Copy(pkpKey.Body, 0, bKey, 3, pkpKey.Body.Length);
						
						byte[] bUserID = new byte[UserID.Body.Length + 5];
						bUserID[0] = 0xb4;
						bUserID[1] = (byte)((UserID.Body.Length >> 24) & 0xFF);
						bUserID[2] = (byte)((UserID.Body.Length >> 16) & 0xFF);
						bUserID[3] = (byte)((UserID.Body.Length >> 8) & 0xFF);
						bUserID[4] = (byte)(UserID.Body.Length & 0xFF);
						Array.Copy(UserID.Body, 0, bUserID, 5, UserID.Body.Length);
						
						byte[] bData = new byte[bUserID.Length + bKey.Length];
						Array.Copy(bKey, 0, bData, 0, bKey.Length);
						Array.Copy(bUserID, 0, bData, bKey.Length, bUserID.Length);
						
						spCert.Verify(bData, pkpSigningKey);
						if(spCert.SignatureStatus == SignatureStatusTypes.Invalid) {
							this.validitystatus = ValidityStatus.Invalid;
							continue;
						} else if(spCert.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available) {
							this.validitystatus = ValidityStatus.ValidationKeyUnavailable;
							continue;
						} else if(spCert.SignatureStatus == SignatureStatusTypes.Not_Verified) {
							this.validitystatus = ValidityStatus.NotYetValidated;
							continue;
						}
					} else {
						//TODO: Add code for v3 Signature verification
						
					}
				}
			}
		}		
		/// <summary>
		/// Creates a new Certification for the UserID.
		/// </summary>
		/// <param name="spSignature">A signaturepacket that has been
		/// prepared for being signed. Things like signature subpackets
		/// MUST already be in place. Only the signature type is
		/// automatically set to UserIDCertification.</param>
		/// <param name="skpKey">A secret key that is used to signed the
		/// certification.</param>
		/// <param name="strPassphrase">The passphrase that fits to the
		/// given secret key packet.</param>
		/// <param name="pkpKey">The public key to which the userid that
		/// is to be signed belongs.</param>
		public void Sign(SignaturePacket spSignature, SecretKeyPacket skpKey, string strPassphrase, PublicKeyPacket pkpKey) {
			if (spSignature.Version == SignaturePacketVersionNumbers.v4) {
				byte[] bKey = new byte[pkpKey.Body.Length + 3];
				bKey[0] = 0x99;
				bKey[1] = (byte)((pkpKey.Body.Length >> 8) & 0xFF);
				bKey[2] = (byte)(pkpKey.Body.Length & 0xFF);
				Array.Copy(pkpKey.Body, 0, bKey, 3, pkpKey.Body.Length);
				
				byte[] bUserID = new byte[UserID.Body.Length + 5];
				bUserID[0] = 0xb4;
				bUserID[1] = (byte)((UserID.Body.Length >> 24) & 0xFF);
				bUserID[2] = (byte)((UserID.Body.Length >> 16) & 0xFF);
				bUserID[3] = (byte)((UserID.Body.Length >> 8) & 0xFF);
				bUserID[4] = (byte)(UserID.Body.Length & 0xFF);
				Array.Copy(UserID.Body, 0, bUserID, 5, UserID.Body.Length);
				
				byte[] bData = new byte[bUserID.Length + bKey.Length];
				Array.Copy(bKey, 0, bData, 0, bKey.Length);
				Array.Copy(bUserID, 0, bData, bKey.Length, bUserID.Length);
				
				spSignature.SignatureType = SignatureTypes.UserIDSignature;
				spSignature.Sign(bData, skpKey, strPassphrase);
				this.alCertificates.Add(spSignature);
			} else {
				throw new System.NotImplementedException("Only v4 signatures are supported so far!");
			}
		}

		public void Revoke(SignaturePacket spSignature, SecretKeyPacket skpKey, string strPassphrase, PublicKeyPacket pkpKey) {
			if (spSignature.Version == SignaturePacketVersionNumbers.v4) {
				byte[] bKey = new byte[pkpKey.Body.Length + 3];
				bKey[0] = 0x99;
				bKey[1] = (byte)((pkpKey.Body.Length >> 8) & 0xFF);
				bKey[2] = (byte)(pkpKey.Body.Length & 0xFF);
				Array.Copy(pkpKey.Body, 0, bKey, 3, pkpKey.Body.Length);
				
				byte[] bUserID = new byte[UserID.Body.Length + 5];
				bUserID[0] = 0xb4;
				bUserID[1] = (byte)((UserID.Body.Length >> 24) & 0xFF);
				bUserID[2] = (byte)((UserID.Body.Length >> 16) & 0xFF);
				bUserID[3] = (byte)((UserID.Body.Length >> 8) & 0xFF);
				bUserID[4] = (byte)(UserID.Body.Length & 0xFF);
				Array.Copy(UserID.Body, 0, bUserID, 5, UserID.Body.Length);
				
				byte[] bData = new byte[bUserID.Length + bKey.Length];
				Array.Copy(bKey, 0, bData, 0, bKey.Length);
				Array.Copy(bUserID, 0, bData, bKey.Length, bUserID.Length);
				
				spSignature.SignatureType = SignatureTypes.CertificationRevocationSignature;
				spSignature.Sign(bData, skpKey, strPassphrase);
				this.alCertificates.Add(spSignature);
			} else {
				throw new System.NotImplementedException("Only v4 signatures are supported so far!");
			}
		}
		
		/// <summary>
		/// Returns a string representation of the current certified UserID.
		/// </summary>
		/// <returns>Returns a string representation of the current certified
		/// UserID.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			return this.UserID.UserID;
		}
		
		public override int GetHashCode() {
			byte[] bUserID = System.Text.Encoding.UTF8.GetBytes(this.UserID.UserID);
			int iReturn = 0;
			for (int i=0; i< bUserID.Length; i++)
				iReturn += bUserID[i];
			
			return iReturn;
		}
		
		public override bool Equals(object o) {
			if (o is CertifiedUserID) {
				CertifiedUserID cuiComp = (CertifiedUserID)o;
				if (cuiComp.UserID.UserID == this.UserID.UserID)
					return true;
			}
			return false;
		}
		
		
		/// <summary>
		/// Generates the certifiedUserID out of the properties
		/// in this.
		/// </summary>
		/// <returns>Returns a byte array containing the openpgp encoded
		/// representation of the certified user ID.</returns>
		/// <remarks>No remarks</remarks>
		public byte[] Generate() {
			byte[] bUserID = this.UserID.Generate();
			
			IEnumerator ieSignatures = this.Certificates.GetEnumerator();
			int lLength = 0;
			while (ieSignatures.MoveNext()) {
				if (ieSignatures.Current is SignaturePacket) {
					lLength += ((SignaturePacket)ieSignatures.Current).Generate().Length;
				}
			}
			
			byte[] bSignatures = new byte[lLength];
			ieSignatures = this.Certificates.GetEnumerator();
			int iPosition = 0;
			while (ieSignatures.MoveNext()) {
				if (ieSignatures.Current is SignaturePacket) {
					byte[] bSign = ((SignaturePacket)ieSignatures.Current).Generate();
					Array.Copy(bSign, 0, bSignatures, iPosition, bSign.Length);
					iPosition += bSign.Length;
				}
			}
			
			byte[] bData = new byte[bUserID.Length + bSignatures.Length];
			Array.Copy(bUserID, 0, bData, 0, bUserID.Length);
			Array.Copy(bSignatures, 0, bData, bUserID.Length, bSignatures.Length);
			
			return bData;
			
		}
		
	}
}

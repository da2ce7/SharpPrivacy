//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// PublicKeyRing.cs: 
// 	Class for handling public key rings.
//
// Author(s):
//	Daniel Fabian (df@sharpprivacy.net)
//  Roberto Rossi
//
//
// Version: 0.2.0
//
// Changelog:
//	- 10.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 18.02.2004: Modified version with additional function by 
//                Roberto Rossi. Added LDAP linking and bug fixs.
// 
//
// (C) 2003-2004, Daniel Fabian, Roberto Rossi
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher.Math;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using System.Collections;
using System.IO;

namespace SharpPrivacy.SharpPrivacyLib {
	
	/// <summary>
	/// Class to manage a KeyRing containing PGP-Armored radix64 encoded Keys
	/// </summary>
	public class PublicKeyRing {
		
		private ArrayList alPublicKeys;
		private bool bIsUpdated = false;
		private string strLoadingPath;
		
		public bool IsUpdated {
			get {
				return bIsUpdated;
			}
		}
		
		/// <summary>
		/// Gets the key list
		/// </summary>
		public ArrayList PublicKeys {
			get {
				return alPublicKeys;
			}
			set {
				alPublicKeys = value;
			}
		}
		
		/// <summary>
		/// Default constructor
		/// </summary>
		public PublicKeyRing() {
			alPublicKeys = new ArrayList();
		}
		
		/// <summary>
		/// Loads a keyring file
		/// </summary>
		/// <param name="strPath">The keyring file location</param>
		public void Load(string strPath) {
			this.strLoadingPath = strPath;
			System.IO.StreamReader srInput = new StreamReader(strPath);
			string strKeys = srInput.ReadToEnd();
			srInput.Close();
			
			this.PublicKeys = new ArrayList();
			
			ArmorTypes atType = new ArmorTypes();
			string strKey = Armor.RemoveArmor(strKeys, ref atType, ref strKeys);
			while (strKey.Length > 0) {
				TransportablePublicKey[] tpkKeys = TransportablePublicKey.SplitKeys(strKey);
				foreach(TransportablePublicKey tpkKey in tpkKeys) {
					this.Add(tpkKey);
				}
				
				strKey = Armor.RemoveArmor(strKeys, ref atType, ref strKeys);
			}
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Saves the keyring to the default location
		/// </summary>
		public void Save() {
			Save(this.strLoadingPath);
		}
		
		/// <summary>
		/// Refreshes the keyring
		/// </summary>
		public void Reload() {
			if (this.strLoadingPath.Length == 0)
				return;
			
			Load(strLoadingPath);
		}
		
		/// <summary>
		/// Saves the keyring to a specific location
		/// </summary>
		/// <param name="strPath">location to save to</param>
		public void Save(string strPath) {
			System.IO.StreamWriter swOutput = new StreamWriter(strPath);
			IEnumerator ieKeys = this.PublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (ieKeys.Current is TransportablePublicKey) {
					try {
						TransportablePublicKey tpkKey = (TransportablePublicKey)ieKeys.Current;
						byte[] bKey = tpkKey.Generate();
						string strKey = Armor.WrapPublicKey(bKey);
						swOutput.Write(strKey);
					} catch (Exception e) {
						throw new Exception("Error while trying to save a public key: " + e.Message);
						//MessageBox.Show("Error while trying to save a public key: " + e.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Warning);
					}
				}
			}
			swOutput.Close();
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Saves a key to a location
		/// </summary>
		/// <param name="strPath">file path</param>
		/// <param name="KeyID">key to save</param>
		public void Save(string strPath, ulong KeyID) {
			System.IO.StreamWriter swOutput = new StreamWriter(strPath);
			try	{
				TransportablePublicKey tpkKey = this.Find(KeyID,false);
				byte[] bKey = tpkKey.Generate();
				string strKey = Armor.WrapPublicKey(bKey);
				swOutput.Write(strKey);
			} catch (Exception e) {
				throw new Exception("Error while trying to save a public key: " + e.Message);
			}
			swOutput.Close();
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Add a key to the keyring
		/// </summary>
		/// <param name="tspk">the key to be added</param>
		public void AddPublicKey(TransportablePublicKey tspk) {
			if(tspk != null) {
				if(this.Find(tspk.PrimaryKey.KeyID, false) == null) {
					this.Add(tspk);
				}
			}
		}

		/// <summary>
		/// Private method to add a key doing checks
		/// </summary>
		/// <param name="tpkKey">the key to be saved</param>
		private void Add(TransportablePublicKey tpkKey) {
			bIsUpdated = true;
			TransportablePublicKey local = null;
			if ((local = this.Find(tpkKey.PrimaryKey.KeyID, false)) == null) {
				alPublicKeys.Add(tpkKey);
			} else {
				TransportablePublicKey joinKey = new TransportablePublicKey();
				joinKey.PrimaryKey = local.PrimaryKey;
				//Revocations
				ArrayList toBeAdded = new ArrayList();
				toBeAdded.AddRange(local.RevocationSignatures);
				toBeAdded.AddRange(tpkKey.RevocationSignatures);
				foreach(SignaturePacket localpacket in local.RevocationSignatures) {
					foreach(SignaturePacket packet in tpkKey.RevocationSignatures) {
						if(localpacket.Body == packet.Body && localpacket.Header == packet.Header) {
							toBeAdded.Remove(packet);
							continue;
						}
					}
				}
				joinKey.RevocationSignatures=toBeAdded;

				//Revokers
				toBeAdded = new ArrayList();
				toBeAdded.AddRange(local.RevocationKeys);
				toBeAdded.AddRange(tpkKey.RevocationKeys);
				foreach(SignaturePacket localpacket in local.RevocationKeys) {
					foreach(SignaturePacket packet in tpkKey.RevocationKeys) {
						if(localpacket.Body == packet.Body && localpacket.Header == packet.Header) {
							toBeAdded.Remove(packet);
							continue;
						}
					}
				}
				joinKey.RevocationKeys=toBeAdded;

				//CERTIFICATES
				toBeAdded = new ArrayList();
				toBeAdded.AddRange(local.Certifications);
				toBeAdded.AddRange(tpkKey.Certifications);
				foreach(CertifiedUserID localpacket in local.Certifications) {
					foreach(CertifiedUserID packet in tpkKey.Certifications) {
						if(localpacket.UserID == packet.UserID) {
							ArrayList certificatesToBeAdded = new ArrayList();
							certificatesToBeAdded.AddRange(localpacket.Certificates);
							certificatesToBeAdded.AddRange(packet.Certificates);
							foreach(SignaturePacket signatureLocal in localpacket.Certificates) {
								foreach(SignaturePacket signature in localpacket.Certificates) {
									if(signatureLocal.Header == signature.Header && signatureLocal.Body == signature.Body) {
										certificatesToBeAdded.Remove(signature);
										continue;
									}
								}
							}
							localpacket.Certificates = certificatesToBeAdded;
							toBeAdded.Remove(packet);
							continue;
						}
					}
				}
				joinKey.Certifications = toBeAdded;

				//SUBKEYS
				toBeAdded = new ArrayList();
				toBeAdded.AddRange(local.SubKeys);
				toBeAdded.AddRange(tpkKey.SubKeys);
				foreach(CertifiedPublicSubkey localpacket in local.SubKeys) {
					foreach(CertifiedPublicSubkey packet in tpkKey.SubKeys) {
						if(localpacket.Subkey.KeyID == packet.Subkey.KeyID) {
							toBeAdded.Remove(packet);
							if(localpacket.KeyBindingSignature == null)
								localpacket.KeyBindingSignature = packet.KeyBindingSignature;
							if(localpacket.RevocationSignature == null)
								localpacket.RevocationSignature = packet.RevocationSignature;
							continue;
						}
					}
				}
				joinKey.SubKeys=toBeAdded;
				
				alPublicKeys.Remove(local);
				alPublicKeys.Add(joinKey);
			}
		}
		
		/// <summary>
		/// Removes a key from the ring
		/// </summary>
		/// <param name="lKeyID">the key to remove</param>
		public void Delete(ulong lKeyID) {
			bIsUpdated = true;
			alPublicKeys.Remove(Find(lKeyID, false));
		}
		
		/// <summary>
		/// Removes a key from the ring
		/// </summary>
		/// <param name="tpkKey">the key to remove</param>
		public void Delete(TransportablePublicKey tpkKey) {
			bIsUpdated = true;
			alPublicKeys.Remove(tpkKey);
		}
		
		/// <summary>
		/// Finds a Key given a keyid. Performs a remote LDAP search if specified.
		/// </summary>
		/// <param name="lKeyID">Key to find</param>
		/// <param name="remote">LDAP search</param>
		/// <returns>a key</returns>
		public TransportablePublicKey Find(ulong lKeyID, bool remote) {
			IEnumerator ieKeys = alPublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				TransportablePublicKey tpkKey = (TransportablePublicKey)ieKeys.Current;
				if (tpkKey.PrimaryKey.KeyID == lKeyID) {
					return tpkKey;
				}
				IEnumerator ieSubkeys = tpkKey.SubKeys.GetEnumerator();
				while (ieSubkeys.MoveNext()) {
					CertifiedPublicSubkey cpsSubkey = (CertifiedPublicSubkey)ieSubkeys.Current;
					if (cpsSubkey.Subkey.KeyID == lKeyID)
						return tpkKey;
				}
			}
			
			if (remote) {
				ldapKeyFinder.KeyFinder kf = new ldapKeyFinder.KeyFinder();
				
				string key = kf.MyLDAPSearch(SharpPrivacyLibrary.LdapKeyServer, SharpPrivacyLibrary.LdapPort,"pgpkey","(pgpsignerid="+lKeyID.ToString("X")+")");
				if (key != null) {
					ArmorTypes atType = new ArmorTypes();
					string strKey = Armor.RemoveArmor(key, ref atType, ref key);
					if (strKey.Length > 0) {
						TransportablePublicKey tpkKey = new TransportablePublicKey(strKey);
						AddPublicKey(tpkKey);
						return tpkKey;
					}
				}
			}
			return null;
		}

		/// <summary>
		/// Find a list of keys which contains the result of the query done using userID as argument.
		/// </summary>
		/// <param name="userID">User ID contained in the keys to list</param>
		/// <returns>a list of keys</returns>
		public ArrayList FindPublicKeysByID(string userID) {
			ArrayList pkList = new ArrayList();
			IEnumerator ieKeys = this.PublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportablePublicKey)) {
					continue;
				}
				TransportablePublicKey key = ((TransportablePublicKey)ieKeys.Current);
				if (key.PrimaryUserID.IndexOf(userID) >= 0) {
					pkList.Add(key);
				}
			}
			return pkList;
		}

		/// <summary>
		/// Find a remote list of keys which contains the result of the query done using userID as argument.
		/// </summary>
		/// <param name="userID">User ID contained in the keys to list</param>
		/// <returns>a list of keys</returns>
		public ArrayList FindRemotePublicKeysByUserID(string userID) {
			ArrayList pkList = new ArrayList();
			ldapKeyFinder.KeyFinder kf = new ldapKeyFinder.KeyFinder();	
			byte result = kf.MyLDAPSearchByID(SharpPrivacyLibrary.LdapKeyServer,SharpPrivacyLibrary.LdapPort,"pgpkeyid","(pgpuserid=*"+userID+"*)");
			if(result == 1) {
				string[] keys = kf.getKeys();
				pkList = new ArrayList(keys);
			}
			return pkList;
		}

		/// <summary>
		/// Finds a remote public key radix64 encoded and server stored
		/// </summary>
		/// <param name="keyID">the keyid of the key as hexadecimal code</param>
		/// <returns>a public key radix64 encoded and PGP armored</returns>
		public string FindRemotePublicKeyByKeyID(string keyID) {
			string key = null;
			ldapKeyFinder.KeyFinder kf = new ldapKeyFinder.KeyFinder();	
			key = kf.MyLDAPSearch(SharpPrivacyLibrary.LdapKeyServer,SharpPrivacyLibrary.LdapPort,"pgpkey","(pgpkeyid="+keyID+")");
			if(key.Length > 0) {
				return key;
			}
			return null;
		}

		/// <summary>
		/// Finds a local or remote key given its fingerprint
		/// </summary>
		/// <param name="fingerprint">fingerprint</param>
		/// <returns>a public key</returns>
		public TransportablePublicKey FindPublicKey(string fingerprint) {
			IEnumerator ieKeys = this.PublicKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportablePublicKey)) {
					continue;
				}
				TransportablePublicKey key = ((TransportablePublicKey)ieKeys.Current);
				if(key.PrimaryKey.Fingerprint.ToString() == fingerprint) {
					return key;
				}
			}			
			
			ldapKeyFinder.KeyFinder kf = new ldapKeyFinder.KeyFinder();	
			string remoteKey = kf.MyLDAPSearch(SharpPrivacyLibrary.LdapKeyServer,SharpPrivacyLibrary.LdapPort,"pgpkey","(pgpsignerid="+fingerprint+")");
			if (remoteKey != null) {
				ArmorTypes atType = new ArmorTypes();
				string strKey = Armor.RemoveArmor(remoteKey, ref atType, ref remoteKey);
				if (strKey.Length > 0) {
					TransportablePublicKey tpkKey = new TransportablePublicKey(strKey);
					AddPublicKey(tpkKey);
					return tpkKey;
				}
			}

			return null;
		}

		/// <summary>
		/// Verifies key signatures
		/// </summary>
		/// <param name="keyID">the key to be verified</param>
		/// <returns>
		/// list of invalid signatures or objects containing invalid signatures:
		/// SignaturePacket
		/// CertifiedUserID
		/// CertifiedPublicSubkey
		/// </returns>
		public ArrayList verifySignatures(ulong keyID) {
			return this.verifySignatures(this.Find(keyID,true));
		}

		/// <summary>
		/// Verifies key signatures
		/// </summary>
		/// <param name="tpkKey">the key to be verified</param>
		/// <returns>
		/// list of invalid signatures or objects containing invalid signatures:
		/// SignaturePacket
		/// CertifiedUserID
		/// CertifiedPublicSubkey
		/// </returns>
		private ArrayList verifySignatures(TransportablePublicKey tpkKey) {
			ArrayList signaturesNotOK = new ArrayList();

			//Verify Revocation Signatures
			foreach(SignaturePacket revocation in tpkKey.RevocationSignatures) {
				if(revocation.KeyID == tpkKey.PrimaryKey.KeyID) {
					PublicKeyPacket pkpKey = tpkKey.FindKey(revocation.KeyID);
					byte[] key = new byte[tpkKey.PrimaryKey.Length];
					tpkKey.PrimaryKey.Header.CopyTo(key,0);
					tpkKey.PrimaryKey.Body.CopyTo(key,tpkKey.PrimaryKey.Header.Length);
					if(pkpKey == null) {
						revocation.SignatureStatus = SignatureStatusTypes.Signing_Key_Not_Available;
						signaturesNotOK.Add(revocation);
					} else {
						revocation.Verify(key,pkpKey);
						if(revocation.SignatureStatus == SignatureStatusTypes.Invalid ||
							revocation.SignatureStatus == SignatureStatusTypes.Not_Verified ||
							revocation.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available)
						{	
							signaturesNotOK.Add(revocation);
						}
					}
				} else {
					TransportablePublicKey revtpkKey = this.Find(revocation.KeyID, true);
					if (revtpkKey != null) {
						foreach (SignaturePacket spPacket in tpkKey.RevocationKeys) {
							foreach (BigInteger revoker in spPacket.FindRevokerKeys()) {
								if(revoker.ToString() == revtpkKey.PrimaryKey.Fingerprint.ToString()) {
									PublicKeyPacket pkpKey = revtpkKey.PrimaryKey;
									byte[] key = new byte[tpkKey.PrimaryKey.Length];
									tpkKey.PrimaryKey.Header.CopyTo(key,0);
									tpkKey.PrimaryKey.Body.CopyTo(key,tpkKey.PrimaryKey.Header.Length);
									revocation.Verify(key,pkpKey);
									if(revocation.SignatureStatus == SignatureStatusTypes.Invalid ||
										revocation.SignatureStatus == SignatureStatusTypes.Not_Verified ||
										revocation.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available)
									{	
										signaturesNotOK.Add(revocation);
									}
								}
							}
						}
					} else {
						revocation.SignatureStatus = SignatureStatusTypes.Signing_Key_Not_Available;
						signaturesNotOK.Add(revocation);
					}
				}
			}

			//Verify UserID
			foreach(CertifiedUserID userId in tpkKey.Certifications) {
				userId.Validate(tpkKey.PrimaryKey,this);
				if(userId.CertificationValidityStatus == CertifiedUserID.ValidityStatus.Invalid ||
					userId.CertificationValidityStatus == CertifiedUserID.ValidityStatus.NotYetValidated ||
					userId.CertificationValidityStatus == CertifiedUserID.ValidityStatus.ValidationKeyUnavailable)
				{
					foreach(SignaturePacket sp in userId.Certificates) {
						if(sp.SignatureStatus != SignatureStatusTypes.Valid)
							signaturesNotOK.Add(sp);
					}
				}
			}
			
			foreach(CertifiedPublicSubkey cps in tpkKey.SubKeys) {
				if(cps.KeyBindingSignature == null) {
					signaturesNotOK.Add(cps);
				} else {
					cps.VerifyKeyBindingSignature(tpkKey.PrimaryKey);
					if(cps.KeyBindingSignature.SignatureStatus == SignatureStatusTypes.Invalid ||
						cps.KeyBindingSignature.SignatureStatus == SignatureStatusTypes.Not_Verified ||
						cps.KeyBindingSignature.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available)
					{
						signaturesNotOK.Add(cps.KeyBindingSignature);
					}
				}

				//Verify Subkey Revocation Signature
				SignaturePacket revocation = cps.RevocationSignature;
				if(revocation != null) {
					if(revocation.KeyID == tpkKey.PrimaryKey.KeyID) {
						byte[] subkey = new byte[cps.Subkey.Length];
						cps.Subkey.Header.CopyTo(subkey,0);
						cps.Subkey.Body.CopyTo(subkey,cps.Subkey.Header.Length);
						subkey[0]=0x99;

						byte[] mainkey = new byte[tpkKey.PrimaryKey.Length];
						tpkKey.PrimaryKey.Header.CopyTo(mainkey,0);
						tpkKey.PrimaryKey.Body.CopyTo(mainkey,tpkKey.PrimaryKey.Header.Length);

						byte[] key = new byte[subkey.Length+mainkey.Length];
						mainkey.CopyTo(key,0);
						subkey.CopyTo(key,mainkey.Length);
						
						revocation.Verify(key,tpkKey.PrimaryKey);
						if(revocation.SignatureStatus == SignatureStatusTypes.Invalid ||
							revocation.SignatureStatus == SignatureStatusTypes.Not_Verified ||
							revocation.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available)
						{	
							signaturesNotOK.Add(revocation);
						}
						
					} else {
						TransportablePublicKey revtpkKey = this.Find(revocation.KeyID, true);
						if(revtpkKey != null) {
							foreach(SignaturePacket spPacket in tpkKey.RevocationKeys) {
								foreach(BigInteger revoker in spPacket.FindRevokerKeys()) {
									if(revoker.ToString() == revtpkKey.PrimaryKey.Fingerprint.ToString()) {
										byte[] subkey = new byte[cps.Subkey.Length];
										cps.Subkey.Header.CopyTo(subkey,0);
										cps.Subkey.Body.CopyTo(subkey,cps.Subkey.Header.Length);
										subkey[0]=0x99;

										byte[] mainkey = new byte[revtpkKey.PrimaryKey.Length];
										tpkKey.PrimaryKey.Header.CopyTo(mainkey,0);
										tpkKey.PrimaryKey.Body.CopyTo(mainkey,revtpkKey.PrimaryKey.Header.Length);

										byte[] key = new byte[subkey.Length+mainkey.Length];
										mainkey.CopyTo(key,0);
										subkey.CopyTo(key,mainkey.Length);

										revocation.Verify(key,revtpkKey.PrimaryKey);
										if(revocation.SignatureStatus == SignatureStatusTypes.Invalid ||
											revocation.SignatureStatus == SignatureStatusTypes.Not_Verified ||
											revocation.SignatureStatus == SignatureStatusTypes.Signing_Key_Not_Available)
										{	
											signaturesNotOK.Add(revocation);
										}
									}
								}
							}
						} else {
							signaturesNotOK.Add(revocation);
						}
					}
				}
			}
			return signaturesNotOK;
		}

		/// <summary>
		/// Verifies a key user id certificetion revocation status
		/// </summary>
		/// <param name="keyID">the key to verify</param>
		/// <param name="userID">the user id to verify</param>
		/// <param name="certifierKeyID">the key that issued the certification</param>
		/// <returns>the revocation status of the user id</returns>
		public bool isRevoked(ulong keyID, string userID, ulong certifierKeyID) {
			TransportablePublicKey tpkKey = this.Find(keyID, true);
			if(tpkKey == null)
				return false;
			bool found = false;
			CertifiedUserID toBeVerified = null;
			foreach(CertifiedUserID cui in tpkKey.Certifications) {
				if(cui.UserID.UserID==userID) {
					found=true;
					toBeVerified = cui;
					break;
				}
			}
			if (!found)
				throw new Exception("UserId not found among Key certificates");
			toBeVerified.Validate(tpkKey.PrimaryKey, this);
			foreach(SignaturePacket sign in toBeVerified.Certificates) {
				if(sign.SignatureType == SignatureTypes.CertificationRevocationSignature && sign.KeyID == certifierKeyID && sign.SignatureStatus == SignatureStatusTypes.Valid && sign.isRevocable()) {
					return true;
				}
			}
			return false;
		}

		/// <summary>
		/// Verifies the revocation status of a key
		/// </summary>
		/// <param name="KeyID">the key to verify</param>
		/// <returns>the revocation status of the key</returns>
		public bool isRevoked(ulong KeyID) {
			TransportablePublicKey tpkKey = this.Find(KeyID, true);
			if(tpkKey == null)
				return false;
			if(tpkKey.PrimaryKey.KeyID == KeyID) {
				ArrayList nvsigatures = this.verifySignatures(tpkKey);
				foreach(SignaturePacket sp in tpkKey.PrimaryUserIDCert.Certificates) {
					if(sp.SignatureType == SignatureTypes.UserIDSignature ||
						sp.SignatureType == SignatureTypes.UserIDSignature_CasualVerification ||
						sp.SignatureType == SignatureTypes.UserIDSignature_NoVerification ||
						sp.SignatureType == SignatureTypes.UserIDSignature_PositivVerification)
					{
						if(!sp.isRevocable())
							return false;
					}
				}
				if(tpkKey.RevocationSignatures == null ||  tpkKey.RevocationSignatures.Count == 0) {	
					return false;
				} else {
					foreach (SignaturePacket revocation in tpkKey.RevocationSignatures) {
						if (revocation.KeyID == tpkKey.PrimaryKey.KeyID) {
							PublicKeyPacket pkpKey = tpkKey.FindKey(revocation.KeyID);
							byte[] key = new byte[tpkKey.PrimaryKey.Length];
							tpkKey.PrimaryKey.Header.CopyTo(key,0);
							tpkKey.PrimaryKey.Body.CopyTo(key,tpkKey.PrimaryKey.Header.Length);
							revocation.Verify(key,pkpKey);
							if(revocation.SignatureStatus == SignatureStatusTypes.Valid) {
								return true;
							} else if(revocation.SignatureStatus == SignatureStatusTypes.Invalid) {
								continue;
							} else {
								continue;
							}
						} else {
							TransportablePublicKey revtpkKey = this.Find(revocation.KeyID, true);
							if(revtpkKey == null)
								return false;
							foreach (SignaturePacket spPacket in tpkKey.RevocationKeys) {
								foreach (BigInteger revoker in spPacket.FindRevokerKeys()) {
									if (revoker.ToString() == revtpkKey.PrimaryKey.Fingerprint.ToString()) {
										PublicKeyPacket pkpKey = revtpkKey.PrimaryKey;
										byte[] key = new byte[tpkKey.PrimaryKey.Length];
										tpkKey.PrimaryKey.Header.CopyTo(key,0);
										tpkKey.PrimaryKey.Body.CopyTo(key,tpkKey.PrimaryKey.Header.Length);
										revocation.Verify(key,pkpKey);
										if(revocation.SignatureStatus == SignatureStatusTypes.Valid) {
											return true;
										} else if(revocation.SignatureStatus == SignatureStatusTypes.Invalid) {
											continue;
										} else {
											continue;
										}
									}
								}
							}
						}
					}
				}
			} else {
				ArrayList signaturesNotOK = this.verifySignatures(tpkKey);
				foreach(CertifiedPublicSubkey cps in tpkKey.SubKeys) {
					if(cps.Subkey.KeyID == KeyID) {
						if(cps.RevocationSignature != null && !signaturesNotOK.Contains(cps.RevocationSignature) && cps.KeyBindingSignature.isRevocable()) {
							ulong issuer = cps.RevocationSignature.KeyID;
							if(issuer == tpkKey.PrimaryKey.KeyID) {
								return true;
							} else {
								foreach(SignaturePacket spPacket in tpkKey.RevocationKeys) {
									foreach(BigInteger revoker in spPacket.FindRevokerKeys()) {
										if(revoker == this.Find(issuer,true).PrimaryKey.Fingerprint) {
											return true;
										}
									}
								}
							}
						}
					}
				}
			}
			return false;
		}
	}
	
}

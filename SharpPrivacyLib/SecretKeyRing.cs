//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SecretKeyRing.cs: 
// 	Class for handling secret key rings.
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
//  - 18.02.2004: Modified version with additional function by 
//                Roberto Rossi. Added LDAP linking and bug fixs.
// 
//
// (C) 2003-2004, Daniel Fabian, Roberto Rossi
//
using System;
using SharpPrivacy.SharpPrivacyLib.OpenPGP;
using SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages;
using System.Collections;
using System.IO;

namespace SharpPrivacy.SharpPrivacyLib {
	
	/// <summary>
	///  Class to manage a KeyRing containing PGP-Armored radix64 encoded Keys
	/// </summary>
	public class SecretKeyRing {
		
		private ArrayList alSecretKeys;
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
		public ArrayList SecretKeys {
			get {
				return alSecretKeys;
			}
			set {
				alSecretKeys = value;
			}
		}
		
		/// <summary>
		/// Default constructor
		/// </summary>
		public SecretKeyRing() {
			alSecretKeys = new ArrayList();
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
		/// Loads a keyring file
		/// </summary>
		/// <param name="strPath">The keyring file location</param>
		public void Load(string strPath) {
			strLoadingPath = strPath;
			System.IO.StreamReader srInput = new StreamReader(strPath);
			string strKeys = srInput.ReadToEnd();
			srInput.Close();
			
			this.SecretKeys = new ArrayList();
			
			ArmorTypes atType = new ArmorTypes();
			string strKey = Armor.RemoveArmor(strKeys, ref atType, ref strKeys);
			while (strKey.Length > 0) {
				TransportableSecretKey[] tskKeys = TransportableSecretKey.SplitKeys(strKey);
				foreach (TransportableSecretKey tskKey in tskKeys) {
					this.SecretKeys.Add(tskKey);
				}
				
				strKey = Armor.RemoveArmor(strKeys, ref atType, ref strKeys);
			}
			bIsUpdated = false;
		}
		
		/// <summary>
		/// Saves the keyring to the default location
		/// </summary>
		public void Save() {
			Save(this.strLoadingPath);
		}
		
		/// <summary>
		/// Saves the keyring to a specific location
		/// </summary>
		/// <param name="strPath">location to save to</param>
		public void Save(string strPath) {
			System.IO.StreamWriter swOutput = new StreamWriter(strPath);
			IEnumerator ieKeys = this.SecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (ieKeys.Current is TransportableSecretKey) {
					try {
						TransportableSecretKey tskKey = (TransportableSecretKey)ieKeys.Current;
						byte[] bKey = tskKey.Generate();
						string strKey = Armor.WrapPrivateKey(bKey);
						swOutput.Write(strKey);
					} catch (Exception e) {
						throw new Exception("Error while trying to save a private key: " + e.Message);
						// MessageBox.Show("Error while trying to save a private key: " + e.Message, "Error...", MessageBoxButtons.OK, MessageBoxIcon.Warning);
					}
				}
			}
			swOutput.Close();
			bIsUpdated = false;
		}
		
		/// <summary>
		/// Saves a key to a location
		/// </summary>
		/// <param name="strPath">file path</param>
		/// <param name="KeyID">key to save</param>
		public void Save(string strPath, ulong KeyID) {
			System.IO.StreamWriter swOutput = new StreamWriter(strPath);
			try {
				TransportableSecretKey tskKey = this.Find(KeyID);
				byte[] bKey = tskKey.Generate();
				string strKey = Armor.WrapPrivateKey(bKey);
				swOutput.Write(strKey);
			} catch (Exception e) {
				throw new Exception("Error while trying to save a private key: " + e.Message);
			}
			swOutput.Close();
			bIsUpdated = false;
		}

		/// <summary>
		/// Private method to add a key doing checks
		/// </summary>
		/// <param name="tspk">key to be added</param>
		public void AddSecretKey(TransportableSecretKey tspk) {
			if(tspk != null) {
				if(this.Find(tspk.PrimaryKey.PublicKey.KeyID) == null) {
					this.Add(tspk);
				}
			}
		}
		
		/// <summary>
		/// Add a key to the keyring
		/// </summary>
		/// <param name="tskKey">the key to be added</param>
		private void Add(TransportableSecretKey tskKey) {
			bIsUpdated = true;
			SecretKeys.Add(tskKey);
		}
		
		/// <summary>
		/// Removes the specified key from the ring
		/// </summary>
		/// <param name="tskKey">the key to remove</param>
		public void Delete(TransportableSecretKey tskKey) {
			bIsUpdated = true;
			SecretKeys.Remove(tskKey);
		}
		
		/// <summary>
		/// Removes the specified key from the ring
		/// </summary>
		/// <param name="lKeyID">the key to remove</param>
		public void Delete(ulong lKeyID) {
			bIsUpdated = true;
			SecretKeys.Remove(Find(lKeyID));
		}
		
		/// <summary>
		/// Finds a key 
		/// </summary>
		/// <param name="lKeyID"the key to be found></param>
		/// <returns>the found key</returns>
		public TransportableSecretKey Find(ulong lKeyID) {
			IEnumerator ieKeys = SecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				TransportableSecretKey tskKey = (TransportableSecretKey)ieKeys.Current;
				if (tskKey.PrimaryKey.PublicKey.KeyID == lKeyID) {
					return tskKey;
				}
				
				IEnumerator ieSubkeys = tskKey.SubKeys.GetEnumerator();
				while (ieSubkeys.MoveNext()) {
					if (!(ieSubkeys.Current is SecretKeyPacket))
						throw new Exception("Expected a secret key packet, but did not find one.");
					
					SecretKeyPacket skpKey = (SecretKeyPacket)ieSubkeys.Current;
					if (skpKey.PublicKey.KeyID == lKeyID) {
						return tskKey;
					}
				}
			}
			return null;
		}
		
		/// <summary>
		/// Finds a list of keys doing a query on the userIDs in the ring
		/// </summary>
		/// <param name="userID">the userID to find</param>
		/// <returns>the list of keys containing such user id</returns>
		public ArrayList FindSecretKeysByID(string userID) {
			ArrayList pkList = new ArrayList();
			IEnumerator ieKeys = SecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportableSecretKey)) {
					continue;
				}
				foreach (UserIDPacket pck in ((TransportableSecretKey)ieKeys.Current).UserIDs) {
					if(pck.UserID.IndexOf(userID) >= 0) {
						pkList.Add((TransportableSecretKey)ieKeys.Current);
					}
				}
			}
			return pkList;
		}
		
		/// <summary>
		/// Finds the key related to the specified fingerprint
		/// </summary>
		/// <param name="fingerprint">fingerprint</param>
		/// <returns>a key</returns>
		public TransportableSecretKey FindSecretKey(string fingerprint) {
			IEnumerator ieKeys = SecretKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				if (!(ieKeys.Current is TransportableSecretKey)) {
					continue;
				}
				if(((TransportableSecretKey)ieKeys.Current).PrimaryKey.PublicKey.Fingerprint.ToString() == fingerprint) {
					return ((TransportableSecretKey)ieKeys.Current);
				}
			}
			return null;
		}
		
	}
	
}

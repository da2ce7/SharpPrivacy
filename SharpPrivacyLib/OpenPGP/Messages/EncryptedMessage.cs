//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// EncryptedMessage.cs: 
// 	Class for handling encrypted messages.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 04.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP.Messages to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages
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
	/// The class encrypted message is a representation of the
	/// openpgp message "Encrypted Message". It contains an
	/// ESK Sequence as well as an symmetrically encrypted
	/// data packet.
	/// This class provides means to handle such messages.
	/// </summary>
	/// <remarks>
	/// The class encrypted message is a representation of the
	/// openpgp message "Encrypted Message". It contains an
	/// ESK Sequence as well as an symmetrically encrypted
	/// data packet.
	/// This class provides means to handle such messages.
	/// </remarks>
	public class EncryptedMessage : Message {
		private ESKSequence esKeys;
		private SymmetricallyEncryptedDataPacket sepData;
		
		/// <summary>
		/// Readonly. Returns true if the message was symmetrically
		/// encrypted. A message is symmentrically encrypted, if the
		/// according ESK Sequence does not contains asymmetrically
		/// encrypted session keys.
		/// </summary>
		/// <value>True if the message was symmetrically
		/// encrypted. A message is symmentrically encrypted, if the
		/// according ESK Sequence does not contains asymmetrically
		/// encrypted session keys.</value>
		/// <remarks>No remarks</remarks>
		public bool SymmetricallyEncrypted {
			get {
				if (esKeys.AsymKeys.Count == 0)
					return true;
				return false;
			}
		}
		
		/// <summary>
		/// Creates a new encrypted message.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public EncryptedMessage() {
			esKeys = new ESKSequence();
		}
		
		/// <summary>
		/// Parses an Encrypted Message out of the given array of packets.
		/// In this special case, the first packets MUST be
		/// either Symmetrically Encrypted Sessionkey Packets or  
		/// Asymmetrically Encrypted Sessionkey Packets, or a mixture.
		/// After one more more sessionkey packet, a symmetrically encrypted
		/// data packet must follow.
		/// </summary>
		/// <returns>Returns the number of packets used by the 
		/// function.</returns>
		/// <param name="packets">Array of packets. The first packets MUST be
		/// either Symmetrically Encrypted Sessionkey Packets or  
		/// Asymmetrically Encrypted Sessionkey Packets, or a mixture.
		/// After one more more sessionkey packet, a symmetrically encrypted
		/// data packet must follow. Otherwise an exception is thrown.</param>
		/// <exception cref="System.Exception">Throws an ordinary
		/// Exception of the given sequence of packets is not an
		/// Encrypted Message.</exception>
		/// <remarks>No remarks</remarks>
		public override int ParseMessage(Packet[] packets) {
			
			int iPos = esKeys.ParseMessage(packets);
			
			if (!(packets[iPos] is SymmetricallyEncryptedDataPacket))
				throw new System.ArgumentException("Expected a symmetrically encrypted data packet, but did not find one!");
			
			sepData = (SymmetricallyEncryptedDataPacket)packets[iPos];
			
			return ++iPos;
			
		}
		
		/// <summary>
		/// Gets the OpenPGP encoded representation of the encrypted
		/// message.
		/// </summary>
		/// <returns>Returns a byte array that contains the binary
		/// representation of the encrypted message.</returns>
		/// <remarks>No remarks</remarks>
		public override byte[] GetEncoded() {
			byte[] bOutput1 = esKeys.GetEncoded();
			byte[] bOutput2 = sepData.Generate();
			
			byte[] bOutput = new byte[bOutput1.Length + bOutput2.Length];
			bOutput1.CopyTo(bOutput, 0);
			bOutput2.CopyTo(bOutput, bOutput1.Length);
			
			return bOutput;
		}
		
		/// <summary>
		/// Finds a secret key out of the given secret keyring that is able
		/// to decrypt the current encrypted message and returns its KeyID.
		/// If such a key is not found, 0 is returned.
		/// </summary>
		/// <param name="skrRing">Secret keyring containing all secret keys
		/// known to the system.</param>
		/// <returns>Returns the KeyID of the key that is able to decrypt the
		/// encrypted message.</returns>
		/// <remarks>No remarks</remarks>
		public ulong GetFittingKeyID(SecretKeyRing skrRing) {
			bool bFound = false;
			
			IEnumerator ieSessionkeys = esKeys.AsymKeys.GetEnumerator();
			while (ieSessionkeys.MoveNext()) {
				if (!(ieSessionkeys.Current is AsymSessionKeyPacket))
					throw new Exception("Strange Error!");
				
				AsymSessionKeyPacket askpKey = (AsymSessionKeyPacket)ieSessionkeys.Current;
				ulong lKeyID = askpKey.KeyID;
				
				TransportableSecretKey tskKey = skrRing.Find(lKeyID);
				if (tskKey != null) {
					return lKeyID;
				}
			}
			
			if (!bFound) 
				throw new Exception("No fitting secret key was found to decrypt the message!");
			
			return 0;
		}
		
		/// <summary>
		/// Decrypts the current encrypted message using the secret keys
		/// in skrKeyRing and the given passphrase.
		/// </summary>
		/// <param name="skrKeyRing">The secret keyring containing all the
		/// secret keys know to the sytem.</param>
		/// <param name="strPassphrase">The passphrase that was used to
		/// encrypt the secret key material in the key that decrypts
		/// the message.</param>
		/// <returns>Returns the message that was encrypted. Usually this is
		/// an compressed or literal message.</returns>
		/// <remarks>No remarks</remarks>
		public Message Decrypt(SecretKeyRing skrKeyRing, string strPassphrase) {
			TransportableSecretKey tskSecretKey = new TransportableSecretKey();
			AsymSessionKeyPacket askpSessionKey = new AsymSessionKeyPacket();
			bool bFound = false;
			
			// let's see, if we can find a fitting Sessionkey packet
			IEnumerator ieSessionkeys = esKeys.AsymKeys.GetEnumerator();
			while (ieSessionkeys.MoveNext()) {
				if (!(ieSessionkeys.Current is AsymSessionKeyPacket))
					throw new Exception("Strange Error!");
				
				AsymSessionKeyPacket askpKey = (AsymSessionKeyPacket)ieSessionkeys.Current;
				ulong lKeyID = askpKey.KeyID;
				
				TransportableSecretKey tskKey = skrKeyRing.Find(lKeyID);
				if (tskKey != null) {
					bFound = true;
					tskSecretKey = tskKey;
					askpSessionKey = askpKey;
				}
			}
			
			if (!bFound) 
				throw new Exception("No fitting secret key was found to decrypt the message!");
			
			askpSessionKey.DecryptSessionKey(tskSecretKey, strPassphrase);
			byte[] bKey = askpSessionKey.SessionKey;
			
			Packet[] pContent = new Packet[0];
			try {
				SymmetricAlgorithm saAlgo = CipherHelper.CreateSymAlgorithm(askpSessionKey.SymmetricAlgorithm);
				pContent = sepData.Decrypt(bKey, saAlgo);
			} catch (Exception e) {
				throw new System.Exception("Decryption of the Message failed: " + e.Message);
			}
			
			// now we need to look what kind of message was hidden in the
			// encrypted data
			
			// it can be either a literal message
			LiteralMessage lmLiteral = new LiteralMessage();
			try {
				int iPos = lmLiteral.ParseMessage(pContent);
				return lmLiteral;
			} catch (Exception) {}
			
			// or an compressed Message
			CompressedMessage cmCompressed = new CompressedMessage();
			try {
				int iPos = cmCompressed.ParseMessage(pContent);
				return cmCompressed;
			} catch (Exception) {}
			
			throw new System.ArgumentException("Encrypted package content is not a valid message!");
		}
		
		/// <summary>
		/// Decrypts the encrypted message if it is a symmetrically encrypted 
		/// message with the passphrase given as argument.
		/// </summary>
		/// <param name="strPassphrase">The passphrase that was used to encrypt
		/// the message</param>
		/// <returns>Returns the message that was encrypted. Usually this is
		/// an compressed or literal message.</returns>
		/// <remarks>No remarks</remarks>
		public Message Decrypt(string strPassphrase) {
			if (esKeys.SymKeys.Count == 0)
				throw new Exception("This message is not symmetrically encrypted. Please provide a keyring rather than a passphrase!");
			
			Packet[] pContent = new Packet[0];
			Packet[] pReturn = new Packet[0];
			
			IEnumerator ieKeys = esKeys.SymKeys.GetEnumerator();
			while (ieKeys.MoveNext()) {
				SymSessionKeyPacket skpKey = (SymSessionKeyPacket)ieKeys.Current;
				byte[] key = skpKey.S2KSpecifier.GetKey(strPassphrase, CipherHelper.CipherKeySize(skpKey.Algorithm));

				try {
					SymmetricAlgorithm saAlgo = CipherHelper.CreateSymAlgorithm(skpKey.Algorithm);
					pContent = sepData.Decrypt(key, saAlgo);
				} catch (System.Security.Cryptography.CryptographicException) {}
				if (pContent.Length > 0) {
					pReturn = pContent;
				}
			}
			
			if (pReturn.Length == 0)
				throw new System.Security.Cryptography.CryptographicException("Wrong passphrase!");
			
			// now we need to look what kind of message was hidden in the
			// encrypted data
			
			// it can be either a literal message
			LiteralMessage lmLiteral = new LiteralMessage();
			try {
				int iPos = lmLiteral.ParseMessage(pReturn);
				return lmLiteral;
			} catch (Exception) {}
			
			// or an compressed Message
			CompressedMessage cmCompressed = new CompressedMessage();
			try {
				int iPos = cmCompressed.ParseMessage(pReturn);
				return cmCompressed;
			} catch (Exception) {}
			
			throw new System.ArgumentException("Encrypted package content is not a valid message!");
		}
		
	}
}

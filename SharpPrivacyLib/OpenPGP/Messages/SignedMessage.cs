//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SignedMessage.cs: 
// 	Class for handling signed messages.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 29.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP.Messages to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// A signed message is a message that simply contains a
	/// signed data. This kind of message is usually found
	/// inside of compressed or encrypted data packets.
	/// This class provides means to easily handle signed 
	/// messages.
	/// </summary>
	/// <remarks>
	/// A signed message is a message that simply contains a
	/// signed data. This kind of message is usually found
	/// inside of compressed or encrypted data packets.
	/// This class provides means to easily handle signed 
	/// messages.
	/// </remarks>
	public class SignedMessage : Message {
		
		private bool bOnePassSigned = false;
		
		private OnePassSignaturePacket opsOnePass;
		private LiteralMessage lmSignedMessage;
		private SignaturePacket spSignature;
		
		/// <summary>
		/// Gets or sets the message that is to be signed
		/// or has already been signed.
		/// </summary>
		/// <value>The message that is to be signed or has
		/// already been signed.</value>
		/// <remarks>No remarks</remarks>
		public LiteralMessage MessageSigned {
			get {
				return lmSignedMessage;
			}
			set {
				lmSignedMessage = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the signaturepacket that represents
		/// the signature of the contained literalmessage.
		/// </summary>
		/// <value>The signaturepacket that represents
		/// the signature of the contained literalmessage.
		/// </value>
		/// <remarks>No remarks.</remarks>
		public SignaturePacket Signature {
			get {
				return spSignature;
			}
			set {
				spSignature = value;
			}
		}
		
		/// <summary>
		/// Returns true if the signed message is one-passed
		/// signed.
		/// </summary>
		/// <value>true if the signed message is one-passed
		/// signed.</value>
		/// <remarks>No remarks.</remarks>
		public bool OnePassSigned {
			get {
				return bOnePassSigned;
			}
			set {
				if (value)
					throw new System.NotImplementedException("Sorry but emitting one-pass signed messages is not yet supported by SharpPrivacy!");
				
				bOnePassSigned = value;
			}
		}
		
		/// <summary>
		/// Creates a new signed data message. By default creates an
		/// ordinary signed message (speak: not a one-pass signed
		/// message).
		/// </summary>
		/// <remarks>No remarks</remarks>
		public SignedMessage() : this(false) {}
		
		/// <summary>
		/// Creates a new signed message.
		/// </summary>
		/// <param name="onepassSigned">A boolean value indication
		/// if the message is one-pass signed or not.</param>
		/// <remarks>Emitting one-pass signed messages is not supported
		/// yet.</remarks>
		public SignedMessage(bool onepassSigned) {
			OnePassSigned = onepassSigned;
			pPackets = new Packet[0];
		}
		
		/// <summary>
		/// Parses a signed message out of the given array of packets.
		/// In this special case, the first packet must be a signature 
		/// packet or a one-pass signature packet. This is followed by
		/// an OpenPGP message and optionally (if the first packet was
		/// a one-pass signature packet) and ordinary signature packet.
		/// </summary>
		/// <returns>Returns the number of packets used by the function.
		/// </returns>
		/// <param name="packets">Array of packets that contains the
		/// signed message.</param>
		/// <remarks>No remarks</remarks>
		public override int ParseMessage(Packet[] packets) {
			
			if (packets[0] is OnePassSignaturePacket) {
				bOnePassSigned = true;
				opsOnePass = (OnePassSignaturePacket)packets[0];
			} else if (packets[0] is SignaturePacket) {
				bOnePassSigned = false;
				spSignature = (SignaturePacket)packets[0];
			} else {
				throw new System.ArgumentException("This does not appear to be a valid OpenPGP signed message!");
			}
			
			Packet[] pMessage = new Packet[packets.Length - 1];
			Array.Copy(packets, 1, pMessage, 0, pMessage.Length);
			lmSignedMessage = new LiteralMessage();
			int iPos = 0;
			
			try {
				iPos = lmSignedMessage.ParseMessage(pMessage);
			} catch (Exception) {}
			
			if (iPos == 0)
				throw new System.ArgumentException("This does not appear to be a valid OpenPGP signed message!");
			
			iPos++;
			if (bOnePassSigned) {
				if (packets[iPos] is SignaturePacket) {
					spSignature = (SignaturePacket)packets[iPos];
					iPos++;
				} else {
					throw new System.ArgumentException("This does not appear to be a valid OpenPGP signed message!");
				}
			}
				
			return iPos;
		}
		
		/// <summary>
		/// Gets the OpenPGP encoded representation of the signed
		/// message.
		/// </summary>
		/// <returns>Returns a byte array that contains the binary
		/// representation of the signed message.</returns>
		/// <remarks>No remarks</remarks>
		public override byte[] GetEncoded() {
			
			byte[] bSignedMessage = lmSignedMessage.GetEncoded();
			byte[] bSignature = spSignature.Generate();
			
			byte[] bReturn = new byte[0];
			if (bOnePassSigned) {
				byte[] bOnePass = opsOnePass.Generate();
				bReturn = new byte[bSignedMessage.Length + bSignature.Length + bOnePass.Length];
				bOnePass.CopyTo(bReturn, 0);
				bSignedMessage.CopyTo(bReturn, bOnePass.Length);
				bSignature.CopyTo(bReturn, bOnePass.Length + bSignedMessage.Length);
			} else {
				bReturn = new byte[bSignedMessage.Length + bSignature.Length];
				bSignature.CopyTo(bReturn, 0);
				bSignedMessage.CopyTo(bReturn, bSignature.Length);
			}
			
			return bReturn;
		}
		
		
		/// <summary>
		/// Verifies the signature of this signed message.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <returns>Returns a SignatureStatusType that contains
		/// whether the signature was valid, invalid or could not be
		/// verified</returns>
		/// <param name="pkrKeyRing">The public keyring containing
		/// all keys known to the local system.</param>
		public SignatureStatusTypes Verify(PublicKeyRing pkrKeyRing) {
			TransportablePublicKey tpkKey = pkrKeyRing.Find(spSignature.KeyID, true);
			
			if (tpkKey == null)
				return SignatureStatusTypes.Signing_Key_Not_Available;
			
			PublicKeyPacket pkpKey = tpkKey.FindKey(spSignature.KeyID);
			
			spSignature.Verify(lmSignedMessage.Binary, pkpKey);
			
			return spSignature.SignatureStatus;
		}
		
	}
}

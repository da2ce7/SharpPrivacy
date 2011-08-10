//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// ESKSequence.cs: 
// 	Class for handling session keys and sequences of session keys.
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
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using System.Collections;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// ESKSequence is an OpenPGP message that contains one 
	/// or more session key packets (can be either public-
	/// key encryption, or summetrical encryption session keys.
	/// </summary>
	/// <remarks>
	/// ESKSequence is an OpenPGP message that contains one 
	/// or more session key packets (can be either public-
	/// key encryption, or summetrical encryption session keys.
	/// </remarks>
	public class ESKSequence : Message {
		
		private ArrayList alSymKeys;
		private ArrayList alAsymKeys;
		
		// we need this arraylist so we can keep track of the
		// original order of session key packets. this is
		// neccessary so signatures that might have been made
		// over the packet can be successfully verified
		private ArrayList alAllKeys;
		private bool bUpdated = false;
		
		/// <summary>
		/// Readonly. Returns an arraylist containing Symmetrically encrypted
		/// session key packets.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An arraylist containing Symmetrically encrypted
		/// session key packets.</value>
		public ArrayList SymKeys {
			get {
				return alSymKeys;
			}
		}
		
		/// <summary>
		/// Readonly. Returns an arraylist containing Asymmetrically 
		/// encrypted session key packets.
		/// </summary>
		/// <remarks>No remarks</remarks>
		/// <value>An arraylist containing Asymmetrically encrypted
		/// session key packets.</value>
		public ArrayList AsymKeys {
			get {
				return alAsymKeys;
			}
		}
		
		/// <summary>
		/// Creates a new ESKSequence without special preferences.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public ESKSequence() {
			pPackets = new Packet[0];
			alSymKeys = new ArrayList();
			alAsymKeys = new ArrayList();
			alAllKeys = new ArrayList();
		}
		
		/// <summary>
		/// Parses an ESK Sequence out of the given array of packets.
		/// In this special case, the first packet in packets MUST be
		/// either a Symmetrically Encrypted Sessionkey Packet or an 
		/// Asymmetrically Encrypted Sessionkey Packet.
		/// </summary>
		/// <returns>Returns the number of packets used by the 
		/// function.</returns>
		/// <param name="packets">Array of packets. The first packet in
		/// the array MUST be either a Symmetrically Encrypted 
		/// Sessionkey Packet or an Asymmetrically Encrypted Sessionkey 
		/// Packet. Otherwise an exception is thrown.</param>
		/// <exception cref="System.Exception">Throws an ordinary
		/// Exception of the given sequence of packets is not an
		/// ESK Sequence.</exception>
		/// <remarks>No remarks</remarks>
		public override int ParseMessage(Packet[] packet) {
			
			int iSessionKeyCount = 0;
			// First packets must be either Symmetric Sessionkey Packets
			// or Public Key Encrypted Sessionkey Packets and we can have
			// quite a number of them
			while ((packet[iSessionKeyCount] is SymSessionKeyPacket) ||
			       (packet[iSessionKeyCount] is AsymSessionKeyPacket)) {
				
				if (packet[iSessionKeyCount] is SymSessionKeyPacket)
					alSymKeys.Add(packet[iSessionKeyCount]);
				
				if (packet[iSessionKeyCount] is AsymSessionKeyPacket)
					alAsymKeys.Add(packet[iSessionKeyCount]);
				
				alAllKeys.Add(packet[iSessionKeyCount]);
				
				iSessionKeyCount++;
			}
			
			// we still have no valid session key
			if (iSessionKeyCount == 0)
				throw new Exception("This is no ESK sequence!");
			
			return iSessionKeyCount;
			
		}
		
		/// <summary>
		/// Adds an symmetrically encrypted session key to the ESK
		/// Sequence.
		/// </summary>
		/// <param name="sskpKey">A symmetrical Session key packet that
		/// is to be added the the ESKSequence.</param>
		/// <remarks>No remarks</remarks>
		public void AddSymSessionKey(SymSessionKeyPacket sskpKey) {
			bUpdated = true;
			alSymKeys.Add(sskpKey);
		}
		
		/// <summary>
		/// Adds an asymmetrically encrypted session key to the ESK
		/// Sequence.
		/// </summary>
		/// <param name="askpKey">An asymmetrical session key packet 
		/// that is to be added to the ESKSequence.</param>
		/// <remarks>No remarks</remarks>
		public void AddAsymSessionKey(AsymSessionKeyPacket askpKey) {
			bUpdated = true;
			alAsymKeys.Add(askpKey);
		}
		
		/// <summary>
		/// Gets the OpenPGP encoded representation of the ESK Sequence.
		/// </summary>
		/// <returns>Returns a byte array that represents the encoded
		/// ESKSequence.</returns>
		/// <remarks>No remarks</remarks>
		public override byte[] GetEncoded() {
			byte[] bOutput = new byte[0];
			
			if (!bUpdated) {
				//nothing was updated, we can reconstruct the message
				//in the exact same order
				IEnumerator ieKeys = alAllKeys.GetEnumerator();
				while (ieKeys.MoveNext()) {
					Packet pKey = (Packet)ieKeys.Current;
					byte[] bKey = pKey.Generate();
					byte[] bOldOutput = new byte[bOutput.Length];
					bOutput.CopyTo(bOldOutput, 0);
					bOutput = new byte[bOldOutput.Length + bKey.Length];
					
					bOldOutput.CopyTo(bOutput, 0);
					bKey.CopyTo(bOutput, bOldOutput.Length);
				}
			} else {
				// At first we will produce the Symmetrically encrypted
				// session key packets
				IEnumerator ieSymKeys = alSymKeys.GetEnumerator();
				while (ieSymKeys.MoveNext()) {
					SymSessionKeyPacket sskpKey = (SymSessionKeyPacket)ieSymKeys.Current;
					byte[] bKey = sskpKey.Generate();
					byte[] bOldOutput = new byte[bOutput.Length];
					bOutput.CopyTo(bOldOutput, 0);
					bOutput = new byte[bOldOutput.Length + bKey.Length];
					
					bOldOutput.CopyTo(bOutput, 0);
					bKey.CopyTo(bOutput, bOldOutput.Length);
				}
				
				// Now come the Public Key encrypted session key packets
				IEnumerator ieAsymKeys = alAsymKeys.GetEnumerator();
				while (ieAsymKeys.MoveNext()) {
					AsymSessionKeyPacket askpKey = (AsymSessionKeyPacket)ieAsymKeys.Current;
					byte[] bKey = askpKey.Generate();
					byte[] bOldOutput = new byte[bOutput.Length];
					bOutput.CopyTo(bOldOutput, 0);
					bOutput = new byte[bOldOutput.Length + bKey.Length];
					
					bOldOutput.CopyTo(bOutput, 0);
					bKey.CopyTo(bOutput, bOldOutput.Length);
				}
				
			}
				
			
			return bOutput;
		}
		
	}
	
}
		

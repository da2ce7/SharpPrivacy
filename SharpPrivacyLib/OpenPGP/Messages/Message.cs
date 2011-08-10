//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// Message.cs: 
// 	Abstract class that defines what a message should look like.
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
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {

	public abstract class Message : object {
		
		protected Packet[] pPackets;
		
		/// <summary>
		/// Returns an array of packets that form the current
		/// message. Readonly property.
		/// </summary>
		/// <value>An array of packets that form the current
		/// message. Readonly property.</value>
		/// <remarks>No remarks</remarks>
		public Packet[] Packets {
			get {
				return pPackets;
			}
		}
		
		/// <summary>
		/// Parses an array of packets into the message
		/// </summary>
		/// <param name="packets">Array of packet that forms the 
		/// message</param>
		/// <returns>Returns the number of packets parsed.</returns>
		/// <remarks>No remarks</remarks>
		public abstract int ParseMessage(Packet[] packets);
		
		/// <summary>
		/// Returns the message in an RFC2440 encoded way
		/// </summary>
		/// <returns>Returns a byte representation of the encoded
		/// message</returns>
		/// <remarks>No remarks</remarks>
		public abstract byte[] GetEncoded();
		
		/// <summary>
		/// Returns a byte array that contains the message in
		/// a form that a hash for signing can be done over the 
		/// message.
		/// </summary>
		/// <returns>a byte array that contains the message in
		/// a form that a hash for signing can be done over the 
		/// message.</returns>
		/// <remarks>No remarks</remarks>
		//public abstract byte[] GetSignatureData();
	}
}

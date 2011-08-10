//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// LiteralMessage.cs: 
// 	Class for handling literal messages.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 08.04.2003: Created this file.
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
	/// A literalmessage is a message that simply contains a
	/// literal data packet. This kind of message is usually found
	/// inside of compressed or encrypted data packets.
	/// This class provides means to easily handle literal data 
	/// messages.
	/// </summary>
	/// <remarks>
	/// A literalmessage is a message that simply contains a
	/// literal data packet. This kind of message is usually found
	/// inside of compressed or encrypted data packets.
	/// This class provides means to easily handle literal data 
	/// messages.
	/// </remarks>
	public class LiteralMessage : Message {
		
		private DataFormatTypes dftDataFormat;
		private String strText;
		private String strFilename;
		private DateTime dtTimeCreated;
		private byte[] bBinary;
		
		
		/// <summary>
		/// Gets or sets the filename of the file that is stored
		/// inside the message. The filename can also be empty
		/// (zero length string). In this case the file is to be
		/// displayed on the screen. If the filename is _console
		/// the content has to be handled extremly carefully and
		/// securly.
		/// </summary>
		/// <value>The filename of the file that is stored
		/// inside the message. The filename can also be empty
		/// (zero length string). In this case the file is to be
		/// displayed on the screen. If the filename is _console
		/// the content has to be handled extremly carefully and
		/// securly.</value>
		/// <remarks>No remarks</remarks>
		public String Filename {
			get {
				return strFilename;
			}
			set {
				strFilename = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the date and time when the message was
		/// created.
		/// </summary>
		/// <value>The date and time when the message was
		/// created.</value>
		/// <remarks>No remarks</remarks>
		public DateTime TimeCreated {
			get {
				return dtTimeCreated;
			}
			set {
				dtTimeCreated = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the dataformat of the literal message. This can be
		/// either Binary or Text.
		/// </summary>
		/// <value>The dataformat of the literal message. This can be
		/// either Binary or Text.</value>
		/// <remarks>No remarks</remarks>
		public DataFormatTypes DataFormat {
			get {
				return dftDataFormat;
			}
			set {
				dftDataFormat = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the text in the literal data message. If the dataformat
		/// of the message is set to binary, an exception is thrown.
		/// </summary>
		/// <value>The text in the literal data message. If the dataformat
		/// of the message is set to binary, an exception is thrown.</value>
		/// <remarks>No remarks</remarks>
		public String Text {
			get {
				if (dftDataFormat == DataFormatTypes.Binary)
					throw new System.ApplicationException("Cannot get binary data in a string!");
				
				if ((strText.Length == 0) && (bBinary.Length > 0))
					strText = System.Text.Encoding.UTF8.GetString(bBinary);
				
				return strText;
			}
			set {
				if (dftDataFormat == DataFormatTypes.Binary)
					throw new System.ApplicationException("Cannot get binary data in a string!");
				
				strText = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the binary data contained in the literal data
		/// message.<br></br>
		/// If the dataformat is set to Text, it will UTF8-decode the
		/// binary data and store it as text.
		/// </summary>
		/// <value>the binary data contained in the literal data
		/// message.<br></br>
		/// If the dataformat is set to Text, it will UTF8-decode the
		/// binary data and store it as text.</value>
		/// <remarks>No remarks</remarks>
		public byte[] Binary {
			get {
				if (dftDataFormat == DataFormatTypes.Text)
					return System.Text.Encoding.UTF8.GetBytes(strText);
				else 
					return bBinary;
			}
			set {
				if (dftDataFormat == DataFormatTypes.Text)
					strText = System.Text.Encoding.UTF8.GetString(value, 0, value.Length);
				else 
					bBinary = value;
			}
		}
		
		/// <summary>
		/// Creates a new literal data message. DataFormat defaults to
		/// BinaryData.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public LiteralMessage() : this(DataFormatTypes.Binary) {}
		
		/// <summary>
		/// Creates a new literal data message with the given dataformat.
		/// </summary>
		/// <param name="dataFormat">The dataformat of the literal Message</param>
		/// <remarks>No remarks</remarks>
		public LiteralMessage(DataFormatTypes dataFormat) {
			dftDataFormat = dataFormat;
			pPackets = new Packet[0];
		}
		
		/// <summary>
		/// Parses a literal message out of the given array of packets.
		/// In this special case, the first packet in packets MUST be
		/// a literal data packet.
		/// </summary>
		/// <returns>Returns the number of packets used by the function.
		/// If everything works fine, it will always return 1.</returns>
		/// <param name="packets">Array of packets. The first packet in
		/// the array MUST be a literal data packet. Otherwise an exception
		/// is thrown.</param>
		/// <remarks>No remarks</remarks>
		public override int ParseMessage(Packet[] packets) {
			if (packets[0] is LiteralDataPacket) {
				this.pPackets = new Packet[1];
				pPackets[0] = packets[0];
				LiteralDataPacket ldpPacket = (LiteralDataPacket)packets[0];
				dftDataFormat = ldpPacket.DataFormat;
				Binary = ldpPacket.LiteralData;
				strFilename = ldpPacket.Filename;
				dtTimeCreated = ldpPacket.TimeCreated;
			} else 
				throw new System.ArgumentException("Expected a literal data packet as first packet in the array, but did not find it. Looks like something went terribly wrong.");
			
			return 1;
		}
		
		/// <summary>
		/// Gets the OpenPGP encoded representation of the literal data
		/// message.
		/// </summary>
		/// <returns>Returns a byte array that contains the binary
		/// representation of the literal message.</returns>
		/// <remarks>No remarks</remarks>
		public override byte[] GetEncoded() {
			if (pPackets.Length > 1)
				throw new System.ApplicationException("A literal data message can contain only one packet. Something /really/ strange happened!");
			
			if (pPackets.Length == 0) {
				pPackets = new Packet[1];
				LiteralDataPacket ldpPacket = new LiteralDataPacket();
				ldpPacket.DataFormat = DataFormat;
				ldpPacket.LiteralData = Binary;
				ldpPacket.Filename = strFilename;
				ldpPacket.TimeCreated = dtTimeCreated;
				pPackets[0] = ldpPacket;
			}
			
			return pPackets[0].Generate();
		}
		
	}
}

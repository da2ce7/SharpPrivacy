//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// CompressedMessage.cs: 
// 	Class for handling compressed messages.
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
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using ICSharpCode.SharpZipLib.Zip.Compression;
using System.IO;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP.Messages {
	
	/// <summary>
	/// Compressedmessage is an openpgp message. the content
	/// of a compressed message is always compressed. This class
	/// provides means to easily handle compressed messages, and to
	/// compress and decompress data.
	/// </summary>
	/// <remarks>
	/// Compressedmessage is an openpgp message. the content
	/// of a compressed message is always compressed. This class
	/// provides means to easily handle compressed messages, and to
	/// compress and decompress data.
	/// </remarks>
	public class CompressedMessage : Message {
		
		private CompressionAlgorithms caAlgorithm;
		private byte[] bCompressedData;
		
		/// <summary>
		/// Defines the compressionalgorithm used to
		/// compress the data. Currently only the
		/// algorithms plaintext and zip are supported.
		/// </summary>
		/// <value>The compressionalgorithm used to
		/// compress the data. Currently only the
		/// algorithms plaintext and zip are supported.
		/// </value>
		/// <remarks>No remarks</remarks>
		public CompressionAlgorithms Algorithm {
			get {
				return caAlgorithm;
			}
			set {
				// TODO - Add code to allow Algorithm Change
				caAlgorithm = value;
			}
		}
		
		/// <summary>
		/// Returns the data compressed with the given algorithm.
		/// This property is readonly. To get the data into this
		/// property, you have to call the function Compress.
		/// </summary>
		/// <value>The data compressed with the given algorithm.
		/// This property is readonly. To get the data into this
		/// property, you have to call the function Compress.</value>
		/// <remarks>No remarks</remarks>
		public byte[] CompressedData {
			get {
				return bCompressedData;
			}
		}
		
		/// <summary>
		/// Creates a new CompressedMessage. Compression algorithm
		/// defaults to zip.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public CompressedMessage() : this(CompressionAlgorithms.ZIP) {}
		
		/// <summary>
		/// Creates a new CompressedMessage
		/// </summary>
		/// <param name="algo">The compressionalgorithm that shall be
		/// used to compress the message.</param>
		/// <remarks>No remarks</remarks>
		public CompressedMessage(CompressionAlgorithms algo) {
			bCompressedData = new byte[0];
			caAlgorithm = algo;
			pPackets = new Packet[0];
		}
		
		/// <summary>
		/// Compresses the given message into this compressed
		/// message.
		/// </summary>
		/// <param name="message">The message that is to be
		/// compressed.</param>
		/// <remarks>No remarks</remarks>
		public void Compress(Message message) {
			Compress(message.GetEncoded());
		}
		
		/// <summary>
		/// Compresses the given byte array with the currently set
		/// algorithm.
		/// </summary>
		/// <param name="bData">A binary array containing the
		/// data that is to be compressed.</param>
		/// <remarks>No remarks</remarks>
		public void Compress(byte[] bData) {
			if (caAlgorithm == CompressionAlgorithms.ZIP) {
				MemoryStream msStream = new MemoryStream();
				DeflaterOutputStream dosCompress = new DeflaterOutputStream(msStream, new Deflater(Deflater.DEFAULT_COMPRESSION, true));
				try {
					dosCompress.Write(bData, 0, bData.Length);
					dosCompress.Close();
					bCompressedData = (byte[])msStream.ToArray();
				} catch (Exception e) {
					throw new System.ApplicationException("Something went wrong during compressing the message: " + e.Message);
				}
			} else if (caAlgorithm == CompressionAlgorithms.Uncompressed) {
				bCompressedData = bData;
			}
		}
		
		/// <summary>
		/// Uncompresses the current compressed message and returns the message that
		/// was inside of the compressed message. Usually this should be a literal
		/// data message.
		/// </summary>
		/// <returns>Returns the message that was inside of the compressed message. 
		/// Usually this should be a literal data message.</returns>
		/// <exception cref="System.Exception">Throws an exception if the content
		/// of the compressed message is not another valid message.</exception>
		/// <remarks>No remarks</remarks>
		public Message Uncompress() {
			if (!(pPackets[0] is CompressedDataPacket))
				throw new System.Exception("You should never see this message. If you do, something in CompressedMessage went terribly wrong!");
			
			CompressedDataPacket cdpPacket = (CompressedDataPacket)pPackets[0];
			Packet[] pContent = cdpPacket.Uncompress();
			
			// A compressed data packet can contain:
			
			// - a literal message
			LiteralMessage lmMessage = new LiteralMessage();
			try {
				int iPos = lmMessage.ParseMessage(pContent);
				return lmMessage;
			} catch (Exception) {}
			
			// - a signed message
			SignedMessage smMessage = new SignedMessage();
			try {
				int iPos = smMessage.ParseMessage(pContent);
				return smMessage;
			} catch (Exception) {}
			
			// TODO: Try to think of other packets that might
			// occur in a compressed data packet
			
			throw new Exception("The content of the compressed message does not appear to be a valid OpenPGP message!");
		}
		
		/// <summary>
		/// Parses a compressed message out of the given array of packets.
		/// In this special case, the first packet in packets MUST be
		/// a compressed data packet.
		/// </summary>
		/// <returns>Returns the number of packets used by the function.
		/// If everything works fine, it will always return 1.</returns>
		/// <param name="packets">Array of packets. The first packet in
		/// the array MUST be a compressed data packet. Otherwise an exception
		/// is thrown.</param>
		/// <remarks>No remarks</remarks>
		public override int ParseMessage(Packet[] packets) {
			if (packets[0] is CompressedDataPacket) {
				this.pPackets = new Packet[1];
				pPackets[0] = packets[0];
				CompressedDataPacket cdpPacket = (CompressedDataPacket)packets[0];
				bCompressedData = cdpPacket.CompressedData;
				caAlgorithm = cdpPacket.Algorithm;
			} else 
				throw new System.ArgumentException("Expected a literal data packet as first packet in the array, but did not find it. Looks like something went terribly wrong.");
			
			return 1;
		}
		
		/// <summary>
		/// Gets the OpenPGP encoded representation of the compressed data
		/// message.
		/// </summary>
		/// <returns>Returns a byte array that contains the binary
		/// representation of the compressed message.</returns>
		/// <remarks>No remarks</remarks>
		public override byte[] GetEncoded() {
			if (pPackets.Length > 1)
				throw new System.ApplicationException("A compressed data message can contain only one packet. Something /really/ strange happened!");
			
			if (pPackets.Length == 0) {
				pPackets = new Packet[1];
				CompressedDataPacket cdpPacket = new CompressedDataPacket();
				cdpPacket.Algorithm = caAlgorithm;
				cdpPacket.CompressedData = bCompressedData;
				pPackets[0] = cdpPacket;
			}
			
			return pPackets[0].Generate();
		}
		
	}
}

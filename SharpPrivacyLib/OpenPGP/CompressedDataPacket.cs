//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// CompressedDataPacket.cs: 
// 	Class for handling and compressing data packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 07.04.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;
using ICSharpCode.SharpZipLib.Zip.Compression;
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {

	public class CompressedDataPacket : Packet {
		
		private byte[] bCompressedData;
		private CompressionAlgorithms caAlgorithm;
		
		public byte[] CompressedData {
			get {
				return bCompressedData;
			}
			set {
				this.bIsUpdated = true;
				bCompressedData = value;
			}
		}
		
		public CompressionAlgorithms Algorithm {
			get {
				return caAlgorithm;
			}
			set {
				this.bIsUpdated = true;
				caAlgorithm = value;
			}
		}
		
		/// <summary>
		/// Creates a new Compressed Data Packet with 
		/// the parameters in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		public CompressedDataPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new compressed data packet. Format defaults
		/// to new packet format.
		/// </summary>
		public CompressedDataPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.Compressed;
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// Returns a string representation of the packet. This is
		/// a human readable formated representation that has nothing
		/// to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the packet.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "Compressed Data Packet:\r\n";
			strReturn += "Algorithm: " + caAlgorithm.ToString() + "\r\n";
			strReturn += "Compressed Data: ";
			for (int i=0; i<this.bCompressedData.Length; i++) {
				string strByte = bCompressedData[i].ToString("x");
				if (strByte.Length < 2) {
					strByte = "0" + strByte;
				}
				strReturn += ":" + strByte;
			}
			strReturn += "\r\n----\r\n\r\n";
			return strReturn;
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an CompressedDataPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			caAlgorithm = (CompressionAlgorithms)bData[0];
			bCompressedData = new byte[bData.Length - 1];
			Array.Copy(bData, 1, bCompressedData, 0, bData.Length - 1);
			this.bIsUpdated = false;
			return this;
		}
		
		/// <summary>
		/// <para>Generates the content of the compressed data 
		/// packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			byte[] bData = new byte[bCompressedData.Length + 1];
			bData[0] = (byte)caAlgorithm;
			Array.Copy(bCompressedData, 0, bData, 1, bCompressedData.Length);
			
			this.bBody = bData;
		}
		
		public Packet[] Uncompress() {
			System.IO.Stream msStream = new System.IO.MemoryStream(bCompressedData);
			InflaterInputStream iisUnpack = new InflaterInputStream(msStream, new Inflater(true));
			byte[] bOutput = new byte[0];
			try {
				byte[] bWorkout = new byte[4096];
				int iSize = iisUnpack.Read(bWorkout, 0, bWorkout.Length);
				while (iSize > 0) {
					byte[] bOldOutput = new byte[bOutput.Length];
					bOutput.CopyTo(bOldOutput, 0);
					bOutput = new byte[bOutput.Length + iSize];
					bOldOutput.CopyTo(bOutput, 0);
					Array.Copy(bWorkout, 0, bOutput, bOldOutput.Length, iSize);
					iSize = iisUnpack.Read(bWorkout, 0, bWorkout.Length);
				}
				iisUnpack.Close();
			} catch (Exception e) {
				// TODO - Throw the exception in the main application
				// System.Windows.Forms.MessageBox.Show(e.ToString());
				throw new System.Exception("Error uncompressing the message: " + e.Message);
			}
			
			return Packet.ParsePackets(bOutput);
			
		}
		 
		
	}
	
}

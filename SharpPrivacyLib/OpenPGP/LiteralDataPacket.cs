//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// LiteralDataPacket.cs: 
// 	Class for handling literal data packets.
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

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {

	public class LiteralDataPacket : Packet {
		
		private DataFormatTypes dftDataFormat;
		private byte[] bLiteralData;
		private string strFilename;
		private DateTime dtTimeCreated;
		
		public string Filename {
			get {
				return strFilename;
			}
			set {
				this.bIsUpdated = true;
				strFilename = value;
			}
		}
		
		public DateTime TimeCreated {
			get {
				return dtTimeCreated;
			}
			set {
				this.bIsUpdated = true;
				dtTimeCreated = value;
			}
		}
		
		public DataFormatTypes DataFormat {
			get {
				return dftDataFormat;
			}
			set {
				this.bIsUpdated = true;
				dftDataFormat = value;
			}
		}
		
		public byte[] LiteralData {
			get {
				return bLiteralData;
			}
			set {
				this.bIsUpdated = true;
				bLiteralData = value;
			}
		}
		
		
		/// <summary>
		/// Creates a new LiteralDataPacket with 
		/// the parameters in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		public LiteralDataPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new LiteralDataPacket. Format defaults
		/// to new packet format.
		/// </summary>
		public LiteralDataPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.LiteralData;
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
			string strReturn = "Literal Data Packet:\r\n";
			strReturn += "DataFormat: " + dftDataFormat.ToString() + "\r\n";
			strReturn += "Data: ";
			if (dftDataFormat == DataFormatTypes.Text) {
				strReturn += System.Text.Encoding.UTF8.GetString(bLiteralData);
			} else {
				for (int i=0; i<bLiteralData.Length; i++) {
					string strByte = bLiteralData[i].ToString("x");
					if (strByte.Length < 2) {
						strByte = "0" + strByte;
					}
					strReturn += ":" + strByte;
				}
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
		/// <returns>Returns an LiteralDataPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			int iPos = 0;
			dftDataFormat = (DataFormatTypes)bData[iPos++];
			
			// next comes the filename
			int iFilenameLength = bData[iPos++];
			if (iFilenameLength > bData.Length - 2) 
				throw new System.ApplicationException("Not a valid LiteralDataPacket!");
			
			byte[] bFilename = new byte[iFilenameLength];
			Array.Copy(bFilename, 0, bData, iPos, iFilenameLength);
			iPos += iFilenameLength;
			if (bFilename.Length > 0)
				strFilename = System.Text.Encoding.UTF8.GetString(bFilename);
			
			// now 4 bytes of data indicating the modification time of the
			// file
			int iTime = bData[iPos++] << 24;
			iTime ^= bData[iPos++] << 16;
			iTime ^= bData[iPos++] << 8;
			iTime ^= bData[iPos++];
			dtTimeCreated = new DateTime(iTime*10000000 + new DateTime(1970, 1, 1).Ticks);
			
			bLiteralData = new byte[bData.Length - iPos];
			Array.Copy(bData, iPos, bLiteralData, 0, bData.Length - iPos);
			
			this.bIsUpdated = false;
			return this;
		}
		
		/// <summary>
		/// <para>Generates the content of the literal data 
		/// packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			int lLength = bLiteralData.Length + 4 + 1 + strFilename.Length + 1;
			byte[] bData = new byte[lLength];
			int iPos = 0;
			bData[iPos++] = (byte)dftDataFormat;
			bData[iPos++] = (byte)strFilename.Length;
			byte[] bFilename = System.Text.Encoding.UTF8.GetBytes(strFilename);
			Array.Copy(bFilename, 0, bData, iPos, bFilename.Length);
			iPos += bFilename.Length;
			
			long iTime = (dtTimeCreated.Ticks - new DateTime(1970, 1, 1).Ticks)/10000000;
			bData[iPos++] = (byte)((iTime >> 24) & 0xFF);
			bData[iPos++] = (byte)((iTime >> 16) & 0xFF);
			bData[iPos++] = (byte)((iTime >> 8) & 0xFF);
			bData[iPos++] = (byte)(iTime & 0xFF);
			
			Array.Copy(bLiteralData, 0, bData, iPos, bLiteralData.Length);
			
			this.bBody = bData;
		}
		
	}
	
}

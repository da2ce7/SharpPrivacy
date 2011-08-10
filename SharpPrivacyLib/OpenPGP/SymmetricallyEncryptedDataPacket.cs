//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// SymmetricallyEncryptedDataPacket.cs: 
// 	Class for handling symmetrically encrypted data packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 18.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {

	public class SymmetricallyEncryptedDataPacket : Packet {
		
		/* This file is intentionally empty.
		 * The only proptery that a symmetrically
		 * encrypted data packet contains is the
		 * encrypted data. It is stored in the
		 * Body property of this class
		 */
		 
		/// <summary>
		/// Creates a new SymmetricallyEncryptedDataPacket with 
		/// the parameters in pSource
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived</param>
		public SymmetricallyEncryptedDataPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new symmetrically encrypted data packet. 
		/// Format defaults to new packet format.
		/// </summary>
		public SymmetricallyEncryptedDataPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.SymEncrypted;
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
			string strReturn = "Symmetrically Encrypted Data Packet:\r\n";
			for (int i=0; i<this.bBody.Length; i++) {
				string strByte = bBody[i].ToString("x");
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
		/// <returns>Returns an SymmetricallyEncryptedDataPacket
		///  that containes the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			//nothing to be done. the body is the encrypted data.
			this.bIsUpdated = false;
			return this;
		}
		
		// we don't need no craftcontent!
		
		public Packet[] Decrypt(byte[] bKey, SymmetricAlgorithm saAlgo) {
			
			saAlgo.Mode = CipherMode.OpenPGP_CFB;
			saAlgo.Key = bKey;
			ICryptoTransform ictDecrypt = saAlgo.CreateDecryptor();
			int iBS = saAlgo.BlockSize >> 3;
			int iLength = bBody.Length - iBS - 2;
			byte[] bOutput = new byte[bBody.Length];
			ictDecrypt.TransformBlock(bBody, 0, bBody.Length, ref bOutput, 0);
			byte[] bFinal = new byte[iLength];
			Array.Copy(bOutput, bFinal, iLength);
			
			Packet[] pReturn = Packet.ParsePackets(bFinal);
			return pReturn;
		}
		
	}
	
}

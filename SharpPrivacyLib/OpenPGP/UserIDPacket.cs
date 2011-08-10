//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// UserIDPacket.cs: 
// 	Class for handling user id packets.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 03.02.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;
using SharpPrivacy.SharpPrivacyLib.Cipher;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// The UserIDPacket class represents a UserID Packet
	/// as specified in the OpenPGP RFC. It allows creating
	/// or modifying UserID Packets.
	/// </summary>
	/// <remarks>No remarks.</remarks>
	public class UserIDPacket : Packet {
		private string strUserID;
		
		/// <summary>
		/// Creates a new UserIDPacket with the parameters
		/// in pSource.
		/// </summary>
		/// <param name="pSource">Packet from which the
		/// parameters are derived.</param>
		/// <remarks>No remarks.</remarks>
		public UserIDPacket(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		/// <summary>
		/// Creates a new userid packet.
		/// </summary>
		/// <remarks>No remarks.</remarks>
		public UserIDPacket() {
			bBody = new byte[0];
			bHeader = new byte[0];
			pfFormat = PacketFormats.New;
			ctContent = ContentTypes.UserID;
			this.bIsUpdated = true;
		}
		
		/// <summary>
		/// Gets or sets the userid as string.
		/// </summary>
		/// <remarks>Usually this is a mailname (Format 
		/// "Firstname Lastname &gt;email@domain.xyz&lt;"), but can be 
		/// anything.</remarks>
		/// <value>The userid as string.</value>
		public string UserID {
			get {
				return strUserID;
			}
			set {
				this.bIsUpdated = true;
				strUserID = value;
			}
		}
		
		/// <summary>
		/// Returns a string representation of the packet. This is
		/// a human readable formated representation that has nothing
		/// to do with OpenPGP or RFC2440
		/// </summary>
		/// <returns>String representation of the packet.</returns>
		/// <remarks>No remarks</remarks>
		public override string ToString() {
			string strReturn = "";
			
			strReturn = "UserID: " + strUserID + "\r\n";
			
			return strReturn + "\r\n----\r\n\r\n";
		}
		
		/// <summary>
		/// Parses the packet given as byte array into the current
		/// class and returns this with the populated parameters.
		/// </summary>
		/// <param name="bData">A byte array containing an OpenPGP
		/// representation of the packet.</param>
		/// <returns>Returns an UserIDPacket that containes
		/// the parsed properties.</returns>
		/// <remarks>No remarks</remarks>
		public override Packet ParsePacket(byte[] bData) {
			UserID = System.Text.Encoding.UTF8.GetString(bData);
			this.bIsUpdated = false;
			return this;
			
		}
		
		/// <summary>
		/// <para>Generates the content of the User ID 
		/// packet and stores the result in the body property 
		/// of the class.</para>
		/// <para>This method SHOULD never be called directly, as it
		/// is called by the method <see cref="Generate">
		/// Generate()</see>.</para>
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected override void CraftContent() {
			byte[] bData = System.Text.Encoding.UTF8.GetBytes(UserID);
			
			this.bBody = bData;
		}
		
	}
}

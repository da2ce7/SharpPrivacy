//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// Packet.cs: 
// 	This class provides static functions for handling packets, and
//	defines the basic structure of a packet. All other packets extend
//	this class.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.2
//
// Changelog:
//  - 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//  - 16.06.2004: Fixed bug in handling packets with partial body
//                length.
//
// (C) 2003 - 2004, Daniel Fabian
//
using System;
using System.Collections;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// <para>Representation of an OpenPGP Packet. All other packet
	/// types extend this class.</para>
	/// <para>The Packet class also provides a static helper function
	/// to parse packets, regardless of there type.</para>
	/// </summary>
	/// <remarks>
	/// Representation of an OpenPGP Packet. All other packet
	/// types extend this class.</para>
	/// <para>The Packet class also provides a static helper function
	/// to parse packets, regardless of there type.</para>
	/// </remarks>
	public class Packet : object {
		
		protected byte[] bHeader = new byte[2];
		protected int lLength = 0;
		protected byte[] bBody;
		protected ContentTypes ctContent;
		protected PacketFormats pfFormat;
		protected bool bIsUpdated = false;
		
		/// <summary>
		/// Default Constructor - Initialises an empty OpenPGP
		/// Packet.
		/// </summary>
		/// <remarks>No remarks</remarks>
		public Packet() {
			this.bHeader = new byte[0];
			this.bBody = new byte[0];
			this.bIsUpdated = true;
			Format = PacketFormats.New;
		}
		
		/// <summary>
		/// Creates the packet according to the parameters set
		/// in the packet given as parameter
		/// </summary>
		/// <param name="pSource">A packet from which the parameters
		/// are copied to this packet. </param>
		/// <remarks>No remarks</remarks>
		public Packet(Packet pSource) {
			lLength = pSource.Length;
			bBody = pSource.Body;
			ctContent = pSource.Content;
			pfFormat = pSource.Format;
			bHeader = pSource.Header;
			this.bIsUpdated = false;
		}
		
		public bool IsUpdated {
			get {
				return bIsUpdated;
			}
		}
		
		/// <summary>
		/// <para>Gives the exact type of the packet. This can be one
		/// of the following:</para>
		/// <list type="bullet">
		/// 	<listheader>
		/// 		<term>Packettypes</term>
		/// 	</listheader>
		/// 	<item><term> Public-Key Encrypted Session Key Packet</term></item>
		/// 	<item><term> Signature Packet</term></item>
		/// 	<item><term> Symmetric-Key Encrypted Session Key Packet</term></item>
		/// 	<item><term> One-Pass Signature Packet</term></item>
		/// 	<item><term> Secret Key Packet</term></item>
		/// 	<item><term> Public Key Packet</term></item>
		/// 	<item><term> Secret Subkey Packet</term></item>
		/// 	<item><term> Compressed Data Packet</term></item>
		/// 	<item><term> Symmetrically Encrypted Data Packet</term></item>
		/// 	<item><term> Marker Packet</term></item>
		/// 	<item><term> Literal Data Packet</term></item>
		/// 	<item><term> Trust Packet</term></item>
		/// 	<item><term> User ID Packet</term></item>
		/// 	<item><term> Public Subkey Packet</term></item>
		/// </list>
		/// </summary>
		/// <value>
		/// <para>The exact type of the packet. This can be one
		/// of the following:</para>
		/// <list type="bullet">
		/// 	<listheader>
		/// 		<term>Packettypes</term>
		/// 	</listheader>
		/// 	<item><term> Public-Key Encrypted Session Key Packet</term></item>
		/// 	<item><term> Signature Packet</term></item>
		/// 	<item><term> Symmetric-Key Encrypted Session Key Packet</term></item>
		/// 	<item><term> One-Pass Signature Packet</term></item>
		/// 	<item><term> Secret Key Packet</term></item>
		/// 	<item><term> Public Key Packet</term></item>
		/// 	<item><term> Secret Subkey Packet</term></item>
		/// 	<item><term> Compressed Data Packet</term></item>
		/// 	<item><term> Symmetrically Encrypted Data Packet</term></item>
		/// 	<item><term> Marker Packet</term></item>
		/// 	<item><term> Literal Data Packet</term></item>
		/// 	<item><term> Trust Packet</term></item>
		/// 	<item><term> User ID Packet</term></item>
		/// 	<item><term> Public Subkey Packet</term></item>
		/// </list>
		/// </value>
		/// <remarks>No remarks</remarks>
		public ContentTypes Content {
			get {
				return ctContent;
			}
			set {
				this.bIsUpdated = true;
				ctContent = value;
			}
		}
		
		/// <summary>
		/// Packetformat. Can be either newpacketformat or
		/// oldpacketformat
		/// </summary>
		/// <value>Packetformat. Can be either newpacketformat or
		/// oldpacketformat</value>
		/// <remarks>No remarks</remarks>
		public PacketFormats Format {
			get {
				return pfFormat;
			}
			set {
				this.bIsUpdated = true;
				pfFormat = value;
			}
		}
		
		/// <summary>
		/// Byte array that forms the header of the OpenPGP
		/// Packet. This cannot be set directly, but you can
		/// either set the headers parameters directly (like
		/// packetformat) or you can use Packet.ParsePackets
		/// to read packets from a byte buffer.
		/// </summary>
		/// <value>the header of the OpenPGP
		/// Packet. This cannot be set directly, but you can
		/// either set the headers parameters directly (like
		/// packetformat) or you can use Packet.ParsePackets
		/// to read packets from a byte buffer.</value>
		/// <remarks>No remarks</remarks>
		public byte[] Header {
			get {
				if (bIsUpdated)
					CraftHeader();
				
				return bHeader;
			}
		}
		
		/// <summary>
		/// Returns the total length of the packet (header length
		/// + body length).
		/// For obvious reasons, this is readonly.
		/// </summary>
		/// <value>the total length of the packet (header length
		/// + body length).
		/// For obvious reasons, this is readonly.</value>
		/// <remarks>No remarks</remarks>
		public int Length {
			get {
				return bBody.Length + bHeader.Length;
			}
		}
		
		/// <summary>
		/// Byte array that forms the body pf the OpenPGP
		/// Packet.
		/// </summary>
		/// <value>the body pf the OpenPGP
		/// Packet.</value>
		/// <remarks>No remarks</remarks>
		public byte[] Body {
			get {
				if (bIsUpdated)
					this.CraftContent();

				return bBody;
			}
			set {
				this.bIsUpdated = true;
				bBody = value;
				lLength = bBody.Length;
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
			strReturn += "Packet Format: " + Format.ToString() + "\r\n";
			
			return strReturn;
		}
		
		/// <summary>
		/// Static function that makes parsing packets easy. Just give
		/// a byte representation of a set of OpenPGP packets as
		/// parameter, and the function returns an array of packets
		/// that are the parsed OpenPGP packets.
		/// </summary>
		/// <param name="bBinaryData">A byte array containing a set
		/// of OpenPGP packets</param>
		/// <returns>Returns an array of packets</returns>
		/// <remarks>No remarks</remarks>
		public static Packet[] ParsePackets(byte[] bBinaryData) {
			ArrayList alPackets	= new ArrayList(100);
			byte[] bTmpData = new byte[bBinaryData.Length];
			Array.Copy(bBinaryData, bTmpData, bBinaryData.Length);
			
			long iCurrentIndex = 0;
			
			while (iCurrentIndex < bBinaryData.Length) {
				Packet pTmpPacket = new Packet();
				Packet pCurrentPacket = pTmpPacket.ParsePacket(bTmpData);
				
				if (pCurrentPacket != null) {
					iCurrentIndex += pCurrentPacket.Length;
					if (pCurrentPacket.Content != ContentTypes.Marker) {
						alPackets.Add(pCurrentPacket);
					}
					
					bTmpData = new byte[bTmpData.Length - pCurrentPacket.Length];
					Array.Copy(bBinaryData, (int)iCurrentIndex, bTmpData, 0, bBinaryData.Length - (int)iCurrentIndex);
				}
				//MessageBox.Show("Parsed a " + pCurrentPacket.Content.ToString() + "Packet. Current Index: " + iCurrentIndex + "/" + bBinaryData.Length);
			}
			
			Packet[] pReturnPackets = new Packet[alPackets.Count];
			IEnumerator iePacketEnum = alPackets.GetEnumerator();
			int iCount = 0;
			while (iePacketEnum.MoveNext()) {
				if (iePacketEnum.Current is Packet) {
					pReturnPackets[iCount++] = (Packet)iePacketEnum.Current;
				}
			}
			
			return pReturnPackets;
			
		}
		
		
		/// <summary>
		/// Static function that makes parsing packets easy. Just give
		/// a Radix64 encoded representation of a set of OpenPGP packets
		/// as parameter, and the function returns an array of packets
		/// that are the parsed OpenPGP packets.
		/// </summary>
		/// <param name="strBase64Text">A string containing the Radix64
		/// representation of a set of OpenPGP packets</param>
		/// <returns>Returns an array of packets</returns>
		/// <remarks>No remarks</remarks>
		public static Packet[] ParsePackets(string strBase64Text) {
			byte[] bData = Radix64.Decode(strBase64Text);
			
			return ParsePackets(bData);
		}
		
		/// <summary>
		/// Parses a single packet out of the given binary
		/// data. Even if there are more than one packets in the byte
		/// array, only the first packet is returned.
		/// </summary>
		/// <param name="bBinaryData">A byte array containing a set
		/// of OpenPGP packets</param>
		/// <returns>Returns an single OpenPGP packets</returns>
		/// <remarks>No remarks</remarks>
		public virtual Packet ParsePacket(byte[] bBinaryData) {
			Packet pReturnPacket = new Packet();
			
			if ((bBinaryData[0] & 0xC0) == 0xC0) {
				pfFormat = PacketFormats.New;
			} else if ((bBinaryData[0] & 0xC0) == 0x80) {
				pfFormat = PacketFormats.Old;
			} else {
				throw(new ArgumentException("This is not a valid OpenPGP Packet"));
			}
			
			
			if (pfFormat == PacketFormats.New) {
				int iBinaryDataPos = 1;
				ctContent = (ContentTypes)(bBinaryData[0] & 0x3F);
				lLength = bBinaryData[1];
				bBody = new byte[0];
				int iHeaderLength = 1;
				//partial body lengths
				while ((lLength > 223) && (lLength < 255)) {
					iBinaryDataPos += 1;
					iHeaderLength++;
					int lPartialBody = 1 << ((int)(lLength & 0x1F));
					int lOldLength = 0;
					if (bBody.Length > 0) {
						byte[] bOldBody = new byte[bBody.Length];
						bBody.CopyTo(bOldBody, 0);
						bBody = new byte[bOldBody.Length + lPartialBody];
						bOldBody.CopyTo(bBody, 0);
						lOldLength = bBody.Length;
					} else {
						bBody = new byte[lPartialBody];
					}
					Array.Copy(bBinaryData, iBinaryDataPos, bBody, bBody.Length - lPartialBody, lPartialBody);
					lLength = bBinaryData[iBinaryDataPos + lPartialBody];
					iBinaryDataPos += lPartialBody;
				} //partial bodies must end with a normal header!
				if (lLength < 192) {
					iHeaderLength++;
					bHeader = new byte[iHeaderLength];
					if (bBody.Length == 0) {
						Array.Copy(bBinaryData, 0, bHeader, 0, 2);
						iBinaryDataPos = 1;
					}
					byte[] bOldBody = new byte[bBody.Length];
					bBody.CopyTo(bOldBody, 0);
					bBody = new byte[bOldBody.Length + lLength];
					bOldBody.CopyTo(bBody, 0);
					Array.Copy(bBinaryData, iBinaryDataPos + 1, bBody, bBody.Length - (int)lLength, (int)lLength);
				} else if ((lLength > 191) && (lLength < 224)) {
					iHeaderLength += 2;
					bHeader = new byte[iHeaderLength];
					if (bBody.Length == 0) {
						Array.Copy(bBinaryData, 0, bHeader, 0, 3);
						iBinaryDataPos = 1;
					}
					lLength = ((bBinaryData[iBinaryDataPos++] - 192) << 8) + bBinaryData[iBinaryDataPos++] + 192;
					byte[] bOldBody = new byte[bBody.Length];
					bBody.CopyTo(bOldBody, 0);
					bBody = new byte[bOldBody.Length + lLength];
					bOldBody.CopyTo(bBody, 0);
					Array.Copy(bBinaryData, iBinaryDataPos, bBody, bBody.Length - (int)lLength, (int)lLength);
				} else if (lLength == 255) {
					iHeaderLength += 5;
					bHeader = new byte[iHeaderLength];
					if (bBody.Length == 0) {
						Array.Copy(bBinaryData, 0, bHeader, 0, 6);
						iBinaryDataPos = 1;
					}
					lLength = (bBinaryData[iBinaryDataPos++] << 24) ^ (bBinaryData[iBinaryDataPos++] << 16) ^
							  (bBinaryData[iBinaryDataPos++] << 8) ^ bBinaryData[iBinaryDataPos++];
					byte[] bOldBody = new byte[bBody.Length];
					bBody.CopyTo(bOldBody, 0);
					bBody = new byte[bOldBody.Length + lLength];
					bOldBody.CopyTo(bBody, 0);
					Array.Copy(bBinaryData, iBinaryDataPos, bBody, bBody.Length - (int)lLength, (int)lLength);
				}
				
			} else {
				ctContent = (ContentTypes)((bBinaryData[0] & 0x3C) >> 2);
				switch (bBinaryData[0] & 0x03) {
					case 0: 
						lLength = bBinaryData[1];
						bHeader = new byte[2];
						break;
					case 1:
						lLength = (bBinaryData[1] << 8) ^ (bBinaryData[2]);
						bHeader = new byte[3];
						break;
					case 2:
						lLength = (bBinaryData[1] << 16) ^ (bBinaryData[2] << 8) ^
								  (bBinaryData[3]);
						bHeader = new byte[4];
						break;
					case 3:
						throw new System.NotSupportedException("Packets of indetermined length are not supported due to security considerations!");
					default:
						throw new System.ApplicationException("This is not a valid Packet!");
				}
				bBody = new byte[lLength];
				Array.Copy(bBinaryData, 0, bHeader, 0, bHeader.Length);
				Array.Copy(bBinaryData, bHeader.Length, bBody, 0, (int)lLength);
			}
			
			this.bIsUpdated = false;
			switch (ctContent) {
				case ContentTypes.AsymSessionKey:
					pReturnPacket = new AsymSessionKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.Compressed:
					pReturnPacket = new CompressedDataPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.LiteralData:
					pReturnPacket = new LiteralDataPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.Marker:
					pReturnPacket = new Packet(this);
					//We can savly ignore Marker packets!
					//MessageBox.Show("This is a marker packet. It is not yet supported.");
					break;
				case ContentTypes.OnePassSignature:
					pReturnPacket = new OnePassSignaturePacket(this);
					//System.Windows.Forms.MessageBox.Show("This is a One Pass Signature Packet. It is not yet supported");
					break;
				//Content is Public Key Packet
				case ContentTypes.PublicKey:
					pReturnPacket = new PublicKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				//Content is Public Subkey Packet. Same format as Public Key Packet
				case ContentTypes.PublicSubkey:
					pReturnPacket = new PublicKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.SecretKey:
					pReturnPacket = new SecretKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.SecretSubkey:
					pReturnPacket = new SecretKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.Signature:
					pReturnPacket = new SignaturePacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.SymEncrypted:
					pReturnPacket = new SymmetricallyEncryptedDataPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.SymSessionKey:
					pReturnPacket = new SymSessionKeyPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				case ContentTypes.Trust:
					pReturnPacket = new Packet(this);
					//throw new Exception("This is a Trust Packet. It is not yet supported");
					break;
				case ContentTypes.UserID:
					pReturnPacket = new UserIDPacket(this);
					pReturnPacket = pReturnPacket.ParsePacket(bBody);
					break;
				default:
					pReturnPacket = new Packet(this);
					//throw new Exception("Sorry, but this is a packet I don't know about!");
					break;
			}
			
			pReturnPacket.bIsUpdated = false;
			return pReturnPacket;
		}
		
		/// <summary>
		/// Generates the content of the packet. Here it is empty,
		/// but every derived OpenPGP packet HAS to implement this
		/// function.
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected virtual void CraftContent() {
		}
		
		/// <summary>
		/// Generates the header of the packet according to the
		/// parameters Format, Content and the length of the packet.
		/// </summary>
		/// <remarks>No remarks</remarks>
		protected void CraftHeader() {
			byte[] bData = new byte[0];
			int iPos = 0;
			if (Format == PacketFormats.New) {
				if (bBody.Length < 192) {
					bData = new byte[2];
					bData[iPos++] = (byte)(0xC0 ^ (byte)Content);
					bData[iPos++] = (byte)(bBody.Length & 0xFF);
				} else if (bBody.Length < 8384) {
					bData = new byte[3];
					bData[iPos++] = (byte)(0xC0 ^ (byte)Content);
					int iLen = bBody.Length - 192;
					bData[iPos++] = (byte)(((iLen >> 8) & 0xFF) + 192);
					bData[iPos++] = (byte)(iLen & 0xFF);
				} else {
					bData = new byte[6];
					bData[iPos++] = (byte)(0xC0 ^ (byte)Content);
					bData[iPos++] = 0xFF;
					bData[iPos++] = (byte)((bBody.Length >> 24) & 0xFF);
					bData[iPos++] = (byte)((bBody.Length >> 16) & 0xFF);
					bData[iPos++] = (byte)((bBody.Length >> 8) & 0xFF);
					bData[iPos++] = (byte)(bBody.Length & 0xFF);
				}
			} else {
				if (bBody.Length <= 0xFF) {
					bData = new byte[2];
					bData[iPos++] = (byte)(0x80 ^ (byte)((byte)Content << 2) ^ 0);
					bData[iPos++] = (byte)(bBody.Length & 0xFF);
				} else if (bBody.Length <= 0xFFFF) {
					bData = new byte[3];
					bData[iPos++] = (byte)(0x80 ^ (byte)((byte)Content << 2) ^ 1);
					bData[iPos++] = (byte)((bBody.Length >> 8) & 0xFF);
					bData[iPos++] = (byte)(bBody.Length & 0xFF);
				} else {
					bData = new byte[5];
					bData[iPos++] = (byte)(0x80 ^ (byte)((byte)Content << 2) ^ 2);
					bData[iPos++] = (byte)((bBody.Length >> 24) & 0xFF);
					bData[iPos++] = (byte)((bBody.Length >> 16) & 0xFF);
					bData[iPos++] = (byte)((bBody.Length >> 8) & 0xFF);
					bData[iPos++] = (byte)(bBody.Length & 0xFF);
				}
			}
			bHeader = bData;
		}
		
		/// <summary>
		/// Returns the OpenPGP encoded Packet as byte array.
		/// </summary>
		/// <returns>The encoded OpenPGP packet</returns>
		/// <remarks>No remarks</remarks>
		public byte[] Generate() {
			if (IsUpdated) {
				CraftContent();
				CraftHeader();
			}
			
			this.bIsUpdated = false;
			
			long lLength = bBody.Length + bHeader.Length;
			byte[] bPacket = new byte[lLength];
			
			Array.Copy(bHeader, bPacket, bHeader.Length);
			Array.Copy(bBody, 0, bPacket, bHeader.Length, bBody.Length);
			
			return bPacket;
		}
		
		
	}
}

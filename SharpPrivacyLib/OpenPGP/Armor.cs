//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// Armor.cs: 
// 	Class for handling the openPGP ascii armor.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 11.03.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
using System;

namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	public class Armor {
		
		public static string RemoveClearSignatureArmor(string strMessage, ref ArmorTypes atType, ref string strSignature) {
			string[] strLines = strMessage.Split('\n');
			string strReturn = "";
			
			/* Codes for Positions:
			 *  0: Not in an OpenPGP Message
			 *  1: Armor Headers
			 *  2: OpenPGP Message
			 *  3: PGP Signature
			 */
			int iPosition = 0;
			
			for (int i=0; i<strLines.Length; i++) {
				if ((strLines[i].Length > 10) && (strLines[i].Substring(0, 2).Trim() == "--") && (iPosition == 2)) {
					strLines[i] = strLines[i].Trim();
					iPosition = 0;
					switch (strLines[i]) {
						case "-----BEGIN PGP SIGNATURE-----":
							string[] strRestLines = new string[strLines.Length - i];
							Array.Copy(strLines, i, strRestLines, 0, strLines.Length - (i+1));
							string strRest = String.Join("\n", strRestLines);
							strSignature = Armor.RemoveArmor(strRest, ref atType, ref strRest);
							return strReturn.Substring(0, strReturn.Length - 2);
							
						default:
							iPosition = 2;
							break;
					}
				}
				
				if (iPosition == 2) {
					strReturn += strLines[i].TrimEnd(null) + "\r\n";
				}
				
				if ((iPosition == 1) && (strLines[i].Trim().Length == 0)) {
					iPosition = 2;
				}
				
				if ((strLines[i].Length > 10) && (strLines[i].Trim().Substring(0, 2) == "--") && (iPosition == 0)) {
					strLines[i] = strLines[i].Trim();
					iPosition = 1;
					switch (strLines[i]) {
						case "-----BEGIN PGP SIGNED MESSAGE-----":
							atType = ArmorTypes.OpenPGPSignature;
							break;
						
						default:
							iPosition = 0;
							break;
					}
				}
			}
			
			return "";
		}
		
		public static string RemoveArmor(string strMessage, ref ArmorTypes atType, ref string strRest) {
			string[] strLines = strMessage.Split('\n');
			string strReturn = "";
			bool foundSignedMessage = false;
			
			/* Codes for Positions:
			 *  0: Not in an OpenPGP Message
			 *  1: Armor Headers
			 *  2: OpenPGP Message
			 */
			int iPosition = 0;
			
			for (int i=0; i<strLines.Length; i++) {
				if ((strLines[i].Length > 10) && (strLines[i].Substring(0, 2).Trim() == "--") && (iPosition == 2)) {
					strLines[i] = strLines[i].Trim();
					iPosition = 0;
					switch (strLines[i]) {
						case "-----END PGP MESSAGE-----":
						case "-----END PGP PUBLIC KEY BLOCK-----":
						case "-----END PGP PRIVATE KEY BLOCK-----":
						case "-----END PGP SIGNATURE-----":
							string[] strRestLines = new string[strLines.Length - (i+1)];
							Array.Copy(strLines, i+1, strRestLines, 0, strLines.Length - (i+1));
							strRest = String.Join("\n", strRestLines);
							return strReturn;
							
						default:
							iPosition = 2;
							break;
					}
				}
				
				if (iPosition == 2) {
					strReturn += strLines[i];
				}
				
				if ((iPosition == 1) && (strLines[i].Trim().Length == 0)) {
					iPosition = 2;
				}
				
				if ((strLines[i].Length > 10) && (strLines[i].Trim().Substring(0, 2) == "--") && (iPosition == 0)) {
					strLines[i] = strLines[i].Trim();
					iPosition = 1;
					switch (strLines[i]) {
						case "-----BEGIN PGP MESSAGE-----":
							atType = ArmorTypes.OpenPGPMessage;
							break;
						
						case "-----BEGIN PGP PUBLIC KEY BLOCK-----":
							atType = ArmorTypes.PublicKeyBlock;
							break;
						
						case "-----BEGIN PGP PRIVATE KEY BLOCK-----":
							atType = ArmorTypes.PrivateKeyBlock;
							break;
						
						case "-----BEGIN PGP SIGNATURE-----":
							if (!foundSignedMessage)
								atType = ArmorTypes.OpenPGPSignature;
							break;

						case "-----BEGIN PGP SIGNED MESSAGE-----":
							atType = ArmorTypes.OpenPGPSignedMessage;
							iPosition = 0;
							foundSignedMessage = true;
							break;
						
						default:
							iPosition = 0;
							break;
					}
				}
			}
			
			return "";
			
		}
		
		/// <summary>
		/// Armors an Radix64 encoded secret key.
		/// </summary>
		/// <param name="strKey">The secret key encoded in radix64.</param>
		/// <returns>Returns the armored secret key.</returns>
		public static string WrapPrivateKey(string strKey) {
			string strReturn = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
            strReturn += "Version: " + SharpPrivacyLibrary.ApplicationVersionInfos + "\r\n\r\n";
			strReturn += strKey;
			strReturn += "-----END PGP PRIVATE KEY BLOCK-----\r\n\r\n";
			

			return strReturn;
		}
		
		/// <summary>
		/// Armors an OpenPGP encoded secret key.
		/// </summary>
		/// <param name="bKey">The secret key encoded in OpenPGP format.</param>
		/// <returns>Returns the armored secret key.</returns>
		public static string WrapPrivateKey(byte[] bKey) {
			return WrapPrivateKey(Radix64.Encode(bKey, true));
		}
		
		/// <summary>
		/// Armors an Radix64 encoded public key.
		/// </summary>
		/// <param name="strKey">The public key encoded in radix64.</param>
		/// <returns>Returns the armored public key.</returns>
		public static string WrapPublicKey(string strKey) {
			string strReturn = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
            strReturn += "Version: " + SharpPrivacyLibrary.ApplicationVersionInfos + "\r\n\r\n";
			strReturn += strKey;
			strReturn += "-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n";
			
			return strReturn;
		}
		
		/// <summary>
		/// Armors an OpenPGP encoded public key.
		/// </summary>
		/// <param name="bKey">The public key encoded in OpenPGP format.</param>
		/// <returns>Returns the armored public key.</returns>
		public static string WrapPublicKey(byte[] bKey) {
			return WrapPublicKey(Radix64.Encode(bKey, true));
		}

		/// <summary>
		/// Armors an Radix64 encoded OpenPGP message.
		/// </summary>
		/// <param name="strKey">The OpenPGP message encoded in radix64.</param>
		/// <returns>Returns the armored OpenPGP message.</returns>
		public static string WrapMessage(string strMessage) {
			string strReturn = "-----BEGIN PGP MESSAGE-----\r\n";
            strReturn += "Version: " + SharpPrivacyLibrary.ApplicationVersionInfos + "\r\n\r\n";
			strReturn += strMessage;
			strReturn += "-----END PGP MESSAGE-----\r\n";
			
			return strReturn;
		}
		
		/// <summary>
		/// Armors a binary formated OpenPGP message.
		/// </summary>
		/// <param name="bKey">The OpenPGP message in binary form.</param>
		/// <returns>Returns the armored OpenPGP message.</returns>
		public static string WrapMessage(byte[] bMessage) {
			return WrapMessage(Radix64.Encode(bMessage, true));
		}
		
		/// <summary>
		/// Armors an OpenPGP Cleartextsignature.
		/// </summary>
		/// <param name="strMessage">The Message that has been signed. Note that it
		/// must not be Dash Escaped before handing it to this function.</param>
		/// <param name="strSignature">The OpenPGP signature of the given 
		/// message formated in Radix64.</param>
		/// <returns>The armored OpenPGP cleartext signature.</returns>
		public static string WrapCleartextSignature(string strMessage, string strSignature) {
			string strFinal = "-----BEGIN PGP SIGNED MESSAGE-----\r\n";
			strFinal += "Hash: SHA1\r\n\r\n";
			strFinal += Radix64.DashEscape(strMessage);
			strFinal += "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
            strFinal += "Version: " + SharpPrivacyLibrary.ApplicationVersionInfos + "\r\n\r\n";
			strFinal += strSignature;
			strFinal += "-----END PGP SIGNATURE-----\r\n";	
			
			return strFinal;
		}

		/// <summary>
		/// Armors an OpenPGP Cleartextsignature.
		/// </summary>
		/// <param name="strSignature">The OpenPGP signature of the given 
		/// message formated in Radix64.</param>
		/// <returns>The armored OpenPGP cleartext signature.</returns>
		public static string WrapCleartextSignature(string strSignature) {
			string strFinal = "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
            strFinal += "Version: " + SharpPrivacyLibrary.ApplicationVersionInfos + "\r\n\r\n";
			strFinal += strSignature;
			strFinal += "-----END PGP SIGNATURE-----\r\n";	
			
			return strFinal;
		}
		
		/// <summary>
		/// Armors an OpenPGP Cleartextsignature.
		/// </summary>
		/// <param name="strMessage">The Message that has been signed. Note that it
		/// must not be Dash Escaped before handing it to this function.</param>
		/// <param name="bSignature">The OpenPGP signature of the given 
		/// message formated in binary.</param>
		/// <returns>The armored OpenPGP cleartext signature.</returns>
		public static string WrapCleatextSignature(string strMessage, byte[] bSignature) {
			return WrapCleartextSignature(strMessage, Radix64.Encode(bSignature, true));
		}
		
		
	}
}

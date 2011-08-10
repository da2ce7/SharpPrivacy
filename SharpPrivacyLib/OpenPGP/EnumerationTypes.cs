//
// This file is part of the source code distribution of SharpPrivacy.
// SharpPrivacy is an Open Source OpenPGP implementation and can be 
// found at http://www.sharpprivacy.net
// It is released under Gnu General Public License and can be used 
// and modified as long as the result is released under GPL too. 
// For a copy of the GPL, please go to www.gnu.org/copyleft/gpl.html 
//
// EnumerationTypes.cs: 
// 	File that contains various enumeration types for all kind of purposes.
//
// Author:
//	Daniel Fabian (df@sharpprivacy.net)
//
//
// Version: 0.1.0 (initial release)
//
// Changelog:
//	- 15.01.2003: Created this file.
//	- 01.06.2003: Added this header for the first beta release.
//  - 14.06.2003: Changed Namespace from SharpPrivacy.OpenPGP to
//                SharpPrivacy.SharpPrivacyLib.OpenPGP
//
// (C) 2003, Daniel Fabian
//
namespace SharpPrivacy.SharpPrivacyLib.OpenPGP {
	
	/// <summary>
	/// Packetformat of an OpenPGP packet
	/// </summary>
	/// <remarks>
	/// Packetformat of an OpenPGP packet
	/// </remarks>
	public enum PacketFormats {
		
		/// <summary>
		/// New packet format.
		/// </summary>
		New = 0xC0,
		
		/// <summary>
		/// Old Packet format
		/// </summary>
		Old = 0x80
	}
	
	/// <summary>
	/// Possible things you can do with a Asymmetrical Key
	/// </summary>
	/// <remarks>
	/// Possible things you can do with a Asymmetrical Key
	/// </remarks>
	public enum AsymActions {
		
		/// <summary>
		/// Encrypt to a public key
		/// </summary>
		Encrypt = 0,
		
		/// <summary>
		/// Sign with a secret key
		/// </summary>
		Sign = 1
	}
	
	
	/// <summary>
	/// String 2 Key Specifier (S2K) types as specified in RFC2440, 
	/// section 3.6.1
	/// </summary>
	/// <remarks>
	/// String 2 Key Specifier (S2K) types as specified in RFC2440, 
	/// section 3.6.1
	/// </remarks>
	public enum String2KeySpecifierTypes {
		
		/// <summary>
		/// Simple S2K with no salt, no iteration
		/// </summary>
		SimpleS2K = 0x00,
		
		/// <summary>
		/// S2K with a salt
		/// </summary>
		SaltedS2K = 0x01,
		
		/// <summary>
		/// iterated AND salted S2K (state of the art, this one
		/// is recommended)
		/// </summary>
		IteraterSaltedS2K = 0x03
	}
	
	
	/// <summary>
	/// What's the status of the signature.
	/// </summary>
	/// <remarks>
	/// What's the status of the signature.
	/// </remarks>
	public enum SignatureStatusTypes {
		
		/// <summary>
		/// The signature has not (yet) been verified. 
		/// </summary>
		Not_Verified = 0,
		
		/// <summary>
		/// The signature has not been verified, because the signing
		/// key is not in the local keyring.
		/// </summary>
		Signing_Key_Not_Available = 1,
		
		/// <summary>
		/// The signature is invalid
		/// </summary>
		Invalid = 2,
		
		/// <summary>
		/// Signature is valid
		/// </summary>
		Valid = 3
	}
	
	/// <summary>
	/// The 4 Armor types in OpenPGP
	/// </summary>
	/// <remarks>
	/// The 4 Armor types in OpenPGP
	/// </remarks>
	public enum ArmorTypes {
		
		/// <summary>
		/// -----BEGIN PGP MESSAGE----- and -----END PGP MESSAGE-----
		/// 
		/// Armor to protect an OpenPGP message
		/// </summary>
		OpenPGPMessage = 0,
		
		/// <summary>
		/// -----BEGIN PGP PUBLIC KEY BLOCK----- and 
		/// -----END PGP PUBLIC KEY BLOCK-----
		/// 
		/// Armor to protect a transportable public key
		/// </summary>
		PublicKeyBlock = 1,
		
		/// <summary>
		/// -----BEGIN PGP PRIVATE KEY BLOCK----- and 
		/// -----END PGP PRIVATE KEY BLOCK-----
		/// 
		/// Armor to protect transportable secret keys
		/// </summary>
		PrivateKeyBlock = 2,
		
		/// <summary>
		/// -----BEGIN PGP SIGNATURE----- and 
		/// -----END PGP SIGNATURE-----
		/// 
		/// Armor to protect signatures
		/// </summary>
		OpenPGPSignature = 3,

		OpenPGPSignedMessage = 4
	}
	
	/// <summary>
	/// Determines wether a revocation information is sensitiv or not.
	/// Used in Signature Subpackets.
	/// </summary>
	/// <remarks>
	/// Determines wether a revocation information is sensitiv or not.
	/// Used in Signature Subpackets.
	/// </remarks>
	public enum RevocationKeyClasses {
		
		/// <summary>
		/// not sensitiv
		/// </summary>
		NonSensitiv = 0x80,
		
		/// <summary>
		/// sensitiv
		/// </summary>
		Sensitiv = 0x80 | 0x40
	}
	
	/// <summary>
	/// This is a list of flags that indicate preferences that the key
	/// holder has about how the key is handled on a key server.
	/// Used in signature subpackets.
	/// </summary>
	/// <remarks>
	/// This is a list of flags that indicate preferences that the key
	/// holder has about how the key is handled on a key server.
	/// Used in signature subpackets.
	/// </remarks>
	public enum KeyserverPreferencesTypes {
		
		/// <summary>
		/// The key holder requests that this key only be modified or
		/// updated by the key holder or an administrator of the key 
		/// server.
		/// </summary>
		No_Modify = 0x80
	}
	
	/// <summary>
	/// A list of binary flags that hold information about a key.
	/// Used in signature subpackets
	/// </summary>
	/// <remarks>
	/// A list of binary flags that hold information about a key.
	/// Used in signature subpackets
	/// </remarks>
	public enum KeyFlagTypes {
		
		/// <summary>
		/// This key may be used to certify other keys.
		/// </summary>
		CertifyKey = 0x01,
		
		/// <summary>
		/// This key may be used to sign data.
		/// </summary>
		DataSigningKey = 0x02,
		
		/// <summary>
		/// This key may be used to encrypt communications.
		/// </summary>
		CommunicationEncryptionKey = 0x04,
		
		/// <summary>
		/// This key may be used to encrypt storage.
		/// </summary>
		StorageEncryptionKey = 0x08,
		
		/// <summary>
		/// The private component of this key may have been split by
		/// a secret-sharing mechanism.
		/// </summary>
		SplitKey = 0x10,
		
		/// <summary>
		/// The private component of this key may be in the
		/// possession of more than one person.
		/// </summary>
		UsedByMorePersons = 0x80
	}
	
	/// <summary>
	/// All the tags that distinguish the packet types from
	/// each other.
	/// </summary>
	/// <remarks>
	/// All the tags that distinguish the packet types from
	/// each other.
	/// </remarks>
	public enum ContentTypes {
		
		/// <summary>
		/// Public-Key Encrypted Session Key Packet
		/// </summary>
		AsymSessionKey = 1,
		
		/// <summary>
		/// Signature Packet
		/// </summary>
		Signature = 2,
		
		/// <summary>
		/// Symmetric-Key Encrypted Session Key Packet
		/// </summary>
		SymSessionKey = 3,
		
		/// <summary>
		/// One-Pass Signature Packet
		/// </summary>
		OnePassSignature = 4,
		
		/// <summary>
		/// Secret Key Packet
		/// </summary>
		SecretKey = 5,
		
		/// <summary>
		/// Public Key Packet
		/// </summary>
		PublicKey = 6,
		
		/// <summary>
		/// Secret Subkey Packet
		/// </summary>
		SecretSubkey = 7,
		
		/// <summary>
		/// Compressed Data Packet
		/// </summary>
		Compressed = 8,
		
		/// <summary>
		/// Symmetrically Encrypted Data Packet
		/// </summary>
		SymEncrypted = 9,
		
		/// <summary>
		/// Marker Packet
		/// </summary>
		Marker = 10,
		
		/// <summary>
		/// Literal Data Packet
		/// </summary>
		LiteralData = 11,
		
		/// <summary>
		/// Trust Packet
		/// </summary>
		Trust = 12,
		
		/// <summary>
		/// User ID Packet
		/// </summary>
		UserID = 13,
		
		/// <summary>
		/// Public Subkey Packet
		/// </summary>
		PublicSubkey = 14
	}
	
	
	/// <summary>
	/// The versions that are defined and supported for
	/// the Public-Key Encrypted Session Key Packet
	/// </summary>
	/// <remarks>
	/// The versions that are defined and supported for
	/// the Public-Key Encrypted Session Key Packet
	/// </remarks>
	public enum AsymSessionKeyPacketVersionNumbers {
		
		/// <summary>
		/// Version 3
		/// </summary>
		v3 = 3,
		
		/// <summary>
		/// Version 2
		/// </summary>
		v2 = 2
	}
	
	
	/// <summary>
	/// The versions that are defined and supported for
	/// the Signature Packet
	/// </summary>
	/// <remarks>
	/// The versions that are defined and supported for
	/// the Signature Packet
	/// </remarks>
	public enum SignaturePacketVersionNumbers {
		
		/// <summary>
		/// Version 3
		/// </summary>
		v3 = 3,
		
		/// <summary>
		/// Version 4
		/// </summary>
		v4 = 4
	}
	
	
	/// <summary>
	/// The versions that are defined and supported for
	/// the Public Key Packet
	/// </summary>
	/// <remarks>
	/// The versions that are defined and supported for
	/// the Public Key Packet
	/// </remarks>
	public enum PublicKeyPacketVersionNumbers {
		
		/// <summary>
		/// Version 2
		/// </summary>
		v2 = 2,
		
		/// <summary>
		/// Version 3
		/// </summary>
		v3 = 3,
		
		/// <summary>
		/// Version 4
		/// </summary>
		v4 = 4
	}
	
	
	/// <summary>
	/// The versions that are defined and supported for
	/// the Symmetric-Key Encrypted Session Key Packet
	/// </summary>
	/// <remarks>
	/// The versions that are defined and supported for
	/// the Symmetric-Key Encrypted Session Key Packet
	/// </remarks>
	public enum SymSessionKeyPacketVersionNumbers {
		
		/// <summary>
		/// Version 4
		/// </summary>
		v4 = 4
	}
	
	
	/// <summary>
	/// All possible Signature Subpacket tags. For the detailed meaning
	/// of each subpacket, please read RFC 2440, section 5.2.3
	/// </summary>
	/// <remarks>
	/// All possible Signature Subpacket tags. For the detailed meaning
	/// of each subpacket, please read RFC 2440, section 5.2.3
	/// </remarks>
	public enum SignatureSubPacketTypes {
		
		/// <summary>
		/// Signature Creation Time Subpacket
		/// </summary>
		SignatureCreationTime = 2,
		
		/// <summary>
		/// Signature Expiration Time Subpacket
		/// </summary>
		SignatureExpirationTime = 3,
		
		/// <summary>
		/// Exportable Signature Subpacket
		/// </summary>
		ExportableSignature = 4,
		
		/// <summary>
		/// Trust Signature Subpacket
		/// </summary>
		TrustSignature = 5,
		
		/// <summary>
		/// Regular Expression Subpacket
		/// </summary>
		RegularExpression = 6,
		
		/// <summary>
		/// Revocable Subpacket
		/// </summary>
		Revocable = 7,
		
		/// <summary>
		/// Key Expiration Time Subpacket
		/// </summary>
		KeyExpirationTime = 9,
		
		/// <summary>
		/// Prefered Symmetric Algorithms Subpacket
		/// </summary>
		PreferedSymmetricAlgorithms = 11,
		
		/// <summary>
		/// Revocation Key Subpacket
		/// </summary>
		RevocationKey = 12,
		
		/// <summary>
		/// Issuer KeyID Subpacket
		/// </summary>
		IssuerKeyID = 16,
		
		/// <summary>
		/// Notation Data Subpacket
		/// </summary>
		NotationData = 20,
		
		/// <summary>
		/// Prefered Hash-Algorithms Subpacket
		/// </summary>
		PreferedHashAlgorithms = 21,
		
		/// <summary>
		/// Prefered Compression-Algorithms Subpacket
		/// </summary>
		PreferedCompressionAlgorithms = 22,
		
		/// <summary>
		/// Keyserver Preferences Subpacket
		/// </summary>
		KeyServerPreferences = 23,
		
		/// <summary>
		/// Prefered Keyserver Subpacket
		/// </summary>
		PreferedKeyServer = 24,
		
		/// <summary>
		/// Primary UserID Packet
		/// </summary>
		PrimaryUserID = 25,
		
		/// <summary>
		/// PolicyURL Subpacket
		/// </summary>
		PolicyURL = 26,
		
		/// <summary>
		/// Key Flags Subpacket
		/// </summary>
		KeyFlags = 27,
		
		/// <summary>
		/// Signers UserID Subpacket
		/// </summary>
		SignersUserID = 28,
		
		/// <summary>
		/// Reason For Revocation Subpacket
		/// </summary>
		ReasonForRevocation = 29
	}
	
	/// <summary>
	/// The available public key algorithms.
	/// </summary>
	/// <remarks>
	/// The available public key algorithms.
	/// </remarks>
	public enum AsymAlgorithms {
		
		/// <summary>
		/// RSA used for both encrypting and signing
		/// </summary>
		RSA_Encrypt_Sign = 1,
		
		/// <summary>
		/// RSA used for encryption only
		/// </summary>
		RSA_Encrypt_Only = 2,
		
		/// <summary>
		/// RSA used for signing only
		/// </summary>
		RSA_Sign_Only = 3,
		
		/// <summary>
		/// ElGamal used for encryption only
		/// </summary>
		ElGamal_Encrypt_Only = 16,
		
		/// <summary>
		/// DSA (DSA is by definition signing only)
		/// </summary>
		DSA = 17,
		
		/// <summary>
		/// ElGamal used for both encryption and signing
		/// </summary>
		ElGama_Encrypt_Sign = 20
	}
	
	
	/// <summary>
	/// The available symmetric key algorithms
	/// </summary>
	/// <remarks>
	/// The available symmetric key algorithms
	/// </remarks>
	public enum SymAlgorithms {
		
		/// <summary>
		/// Plaintext, not encrypted
		/// </summary>
		Plaintext = 0,
		// IDEA = 1, 		// IDEA is not supported due to patent issues
		
		/// <summary>
		/// Triple DES
		/// </summary>
		Triple_DES = 2,
		
		/// <summary>
		/// CAST5-128
		/// </summary>
		CAST5 = 3,
		// Blowfish = 4, 	// Blowfish is not yet supported
		// SAFER = 5,		// SAFER has yet to be implemented
		// DES_SK = 6,		// DES-SK is not yet specified
		
		/// <summary>
		/// AES with a keysize of 128 bits
		/// </summary>
		AES128 = 7,
		
		/// <summary>
		/// AES with a keysize of 192 bits
		/// </summary>
		AES192 = 8,
		
		/// <summary>
		/// AES with a keysize of 256 bits
		/// </summary>
		AES256 = 9
	}
	
	
	/// <summary>
	/// The available compression algorithms
	/// </summary>
	/// <remarks>
	/// The available compression algorithms
	/// </remarks>
	public enum CompressionAlgorithms {
		
		/// <summary>
		/// Not at all compressed
		/// </summary>
		Uncompressed = 0,
		
		/// <summary>
		/// Compressed with ZIP
		/// </summary>
		ZIP = 1
		// ZLIB = 2			// ZLIB is not yet implemented
	}
	
	
	/// <summary>
	/// The available Hash Algorithms
	/// </summary>
	/// <remarks>
	/// The available Hash Algorithms
	/// </remarks>
	public enum HashAlgorithms {
		
		/// <summary>
		/// MD5
		/// </summary>
		MD5 = 1,
		
		/// <summary>
		/// SHA1
		/// </summary>
		SHA1 = 2
		// RIPE-MD160 = 3,	// RIPE is not implemented yet
		// SHA1_Double = 4,	//Double width SHA1 is not yet specified	
		// MD2 = 5,			// MD2 is not implemented due to security issues
		// TIGER192 = 6,	// Tiger is not implemented yet
		// HAVAL-5-160 = 7	// HAVEL is yet to be specified
		
	}
	
	
	/// <summary>
	/// Data format of the data contained in a literal data packet.
	/// </summary>
	/// <remarks>
	/// Data format of the data contained in a literal data packet.
	/// </remarks>
	public enum DataFormatTypes {
		
		/// <summary>
		/// Binary coded data
		/// </summary>
		Binary = 0x62,
		
		/// <summary>
		/// UTF-8 representation of a string
		/// </summary>
		Text = 0x74
	}
	
	
	/// <summary>
	/// The different signature types. For a detailed description
	/// of the signature types, please check RFC2440, section 5.2.1
	/// </summary>
	/// <remarks>
	/// The different signature types. For a detailed description
	/// of the signature types, please check RFC2440, section 5.2.1
	/// </remarks>
	public enum SignatureTypes {
		
		/// <summary>
		/// Signature over a binary
		/// </summary>
		BinarySignature = 0x00,
		
		/// <summary>
		/// Signature over some text
		/// </summary>
		TextSignature = 0x01,
		
		/// <summary>
		/// standalone signature
		/// </summary>
		StandaloneSignature = 0x02,
		
		/// <summary>
		/// Signes a userID in a key
		/// </summary>
		UserIDSignature = 0x10,
		
		/// <summary>
		/// Signes a UserID that has not been verified
		/// </summary>
		UserIDSignature_NoVerification = 0x11,
		
		/// <summary>
		/// Signes a UserID that has been casually verified
		/// </summary>
		UserIDSignature_CasualVerification = 0x12,
		
		/// <summary>
		/// Signes a UserID that has been positivly verified
		/// </summary>
		UserIDSignature_PositivVerification = 0x13,
		
		/// <summary>
		/// Binds a subkey to the primary key.
		/// </summary>
		SubkeyBindingSignature = 0x18,
		
		/// <summary>
		/// Key signature
		/// </summary>
		KeySignature = 0x1F,
		
		/// <summary>
		/// Key revocation signature
		/// </summary>
		KeyRevocationSignature = 0x20,
		
		/// <summary>
		/// subkey revocation signature
		/// </summary>
		SubkeyRevocationSignature = 0x28,
		
		/// <summary>
		/// Revoces a certificate
		/// </summary>
		CertificationRevocationSignature = 0x30,
		
		/// <summary>
		/// signes the timestamp
		/// </summary>
		TimestampSignature = 0x40
	}
	

	
	
}

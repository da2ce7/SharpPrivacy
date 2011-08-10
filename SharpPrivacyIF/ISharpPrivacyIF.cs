// project created on 14.06.2003 at 17:33
using System;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyIF {
	
	public interface ISharpPrivacyIF {
		
		void SetKeyringPath(string strPublicPath, string strSecretPath);
		
		string EncryptText(string strMessage, ulong[] lTargetKeyIDs);
		void EncryptFile(string strPath, string strOutput, ulong[] lTargetKeyIDs);
		
		string EncryptAndSignText(string strMessage, ulong[] lTargetKeyIDs, ulong lSignatureKeyID, string strPassphrase);
		void EncryptAndSignFile(string strPath, string strOutput, ulong[] lTargetKeyIDs, ulong lSignatureKeyID, string strPassphrase);
		
		string SignText(string strMessage, ulong lSignatureKeyID, string strPassphrase);
		void SignFile(string strPath, string strOutput, ulong lSignatureKeyID, string strPassphrase);

		ulong GetDecryptionKey(string strMessage);
		ulong GetDecryptionKeyFromFile(string strPath);
		string DecryptAndVerify(string strMessage, string strPassphrase);
		string DecryptAndVerifyFile(string strPath, string strPassphrase);
		
		string GetPublicKeysProperties();
		string GetPublicKeyProperties(ulong lKeyID);
		
		string GetSecretKeysProperties();
		string GetSecretKeyProperties(ulong lKeyID);
		
		string GetPublicKey(ulong lKeyID);
		string GetSecretKey(ulong lKeyID, string strPassphrase);
		
		void RemovePublicKey(ulong lKeyID);
		void RemoveSecretKey(ulong lKeyID);
		
		void GenerateKey(string strName, string strEmail, string strKeyType, int iKeySize, long lExpiration, string strPassphrase);
		void SignKey(ulong lSignedKeyID, ulong lSigningKeyID, string strUserID, int nIntroducerDepth, bool bIsExportable, int nSignatureType, string strPassphrase);
		void AddUserID(ulong lKeyID, string strName, string strEmail, string strPassphrase);		
		
		void AddKey(string strKey);
	
	}
}

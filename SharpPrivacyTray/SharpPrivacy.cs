// created on 17.06.2003 at 20:16

using SharpPrivacy.SharpPrivacyIF;
using System;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Xml;

namespace SharpPrivacy.SharpPrivacyTray {
	
	public sealed class SharpPrivacy {
		private static volatile ISharpPrivacyIF instance = null;
		private static XmlDocument xmlSecretKeyRing = null;
		private static XmlDocument xmlPublicKeyRing = null;
		private static object syncRoot = new object();
		
		// make the default constructor private, so that no can directly create it.
		private SharpPrivacy() {
		}

		// public property that can only get the single instance of this class.
		public static ISharpPrivacyIF Instance {
			get {
				// only create a new instance if one doesn't already exist.
				if (instance == null) {
					// use this lock to ensure that only one thread is access
					// this block of code at once.
					lock (syncRoot) {
						if (instance == null) {
							HttpChannel c = new HttpChannel();
							ChannelServices.RegisterChannel(c);
							
							instance = (ISharpPrivacyIF)Activator.GetObject(typeof(ISharpPrivacyIF),"http://localhost:4433/SharpPrivacy", WellKnownObjectMode.Singleton);
							ReloadKeyRing();
						}
					}
				}
				// return instance where it was just created or already existed.
				return instance;
			}
		}
		
		public static XmlElement PublicKeyRing {
			get {
				if (xmlPublicKeyRing != null)
					return xmlPublicKeyRing.DocumentElement;
				
				return null;
			}
		}
		
		public static XmlElement SecretKeyRing {
			get {
				if (xmlSecretKeyRing != null)
					return xmlSecretKeyRing.DocumentElement;
				
				return null;
			}
		}
		
		public static void ReloadKeyRing() {
			string strPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal);
			string strSecret = strPath + "/SharpPrivacy/sec_keyring.txt";
			string strPublic = strPath + "/SharpPrivacy/pub_keyring.txt";
			Instance.SetKeyringPath(strPublic, strSecret);
			
			string strPublicKeys = instance.GetPublicKeysProperties();
			string strSecretKeys = instance.GetSecretKeysProperties();
			if (xmlPublicKeyRing == null)
				xmlPublicKeyRing = new XmlDocument();
			
			if (xmlSecretKeyRing == null)
				xmlSecretKeyRing = new XmlDocument();
			
			xmlPublicKeyRing.LoadXml(strPublicKeys);
			xmlSecretKeyRing.LoadXml(strSecretKeys);
		}
	}
}

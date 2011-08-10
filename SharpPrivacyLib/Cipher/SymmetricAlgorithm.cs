//
// System.Security.Cryptography SymmetricAlgorithm Class implementation
//
// Authors:
//   Thomas Neidhart (tome@sbox.tugraz.at)
//   Sebastien Pouliot (spouliot@motus.com)
//
// Portions (C) 2002 Motus Technologies Inc. (http://www.motus.com)
//
// Modified by Daniel Fabian to fit SharpPrivacy's needs.
// This file is part of the SharpPrivacy source code contribution.
// Get get the original SymmetricAlgorithm class, please visit the
// mono project at http://www.go-mono.com.
// Changes (C) 2003 Daniel Fabian

using System;

namespace SharpPrivacy.SharpPrivacyLib.Cipher {

	// This class implement most of the common code required for symmetric
	// algorithm transforms, like:
	// - CipherMode: Builds CBC and CFB on top of (descendant supplied) ECB
	// - PaddingMode, transform properties, multiple blocks, reuse...
	//
	// Descendants MUST:
	// - intialize themselves (like key expansion, ...)
	// - override the ECB (Electronic Code Book) method which will only be
	//   called using BlockSize byte[] array.
	internal abstract class SymmetricTransform : ICryptoTransform {
		protected SymmetricAlgorithm algo;
		protected bool encrypt;
		private int BlockSizeByte;
		private byte[] temp;
		private byte[] temp2;
		private byte[] workBuff;
		private byte[] workout;
		private byte[] openPGPStart; // needed for openpgp's CFB
		private int FeedBackByte;
		private int FeedBackIter;
		private bool m_disposed = false;
		
		public SymmetricTransform (SymmetricAlgorithm symmAlgo, bool encryption, byte[] rgbIV) {
			algo = symmAlgo;
			encrypt = encryption;
			BlockSizeByte = (algo.BlockSize >> 3);
			// mode buffers
			temp = new byte [BlockSizeByte];
			Array.Copy (rgbIV, 0, temp, 0, BlockSizeByte);
			temp2 = new byte [BlockSizeByte];
			FeedBackByte = (algo.FeedbackSize >> 3);
			FeedBackIter = (int) BlockSizeByte / FeedBackByte;
			//FeedBackIter = 1;
			// transform buffers
			workBuff = new byte [BlockSizeByte];
			workout =  new byte [BlockSizeByte];
			
			//OpenPGP CFB needs an all zero IV
			if (algo.Mode == CipherMode.OpenPGP_CFB) {
				algo.IV = new byte[algo.BlockSize >> 3];
			}
			
			// needed for openpgp's ciphertext feedback mode
			openPGPStart = new byte[(algo.BlockSize >> 3) + 2];
		}
		
		~SymmetricTransform () {
			Dispose (false);
		}

		void IDisposable.Dispose () {
			Dispose (true);
			GC.SuppressFinalize (this);  // Finalization is now unnecessary
		}

		// MUST be overriden by classes using unmanaged ressources
		// the override method must call the base class
		protected void Dispose (bool disposing) {
			if (!m_disposed) {
				if (disposing) {
					// dispose managed object: zeroize and free
					Array.Clear (temp, 0, BlockSizeByte);
					temp = null;
					Array.Clear (temp2, 0, BlockSizeByte);
					temp2 = null;
				}
				m_disposed = true;
			}
		}

		public virtual bool CanTransformMultipleBlocks {
			get { return true; }
		}

		public bool CanReuseTransform {
			get { return false; }
		}

		public virtual int InputBlockSize {
			get { return BlockSizeByte; }
		}

		public virtual int OutputBlockSize {
			get { return BlockSizeByte; }
		}

		// note: Each block MUST be BlockSizeValue in size!!!
		// i.e. Any padding must be done before calling this method
		protected void Transform (byte[] input, byte[] output) {
			switch (algo.Mode) {
			case CipherMode.ECB:
				ECB(input, output);
				break;
			case CipherMode.CBC:
				CBC(input, output);
				break;
			case CipherMode.CFB:
				CFB(input, output);
				break;
			case CipherMode.OFB:
				OFB(input, output);
				break;
			case CipherMode.CTS:
				CTS(input, output);
				break;
			case CipherMode.OpenPGP_CFB:
				CFB(input, output);
				break;
			default:
				throw new NotImplementedException("Unkown CipherMode" + algo.Mode.ToString ());
			}
		}

		// Electronic Code Book (ECB)
		protected abstract void ECB (byte[] input, byte[] output); 

		// Cipher-Block-Chaining (CBC)
		protected virtual void CBC (byte[] input, byte[] output) {
			if (encrypt) {
				for (int i = 0; i < BlockSizeByte; i++)
					temp[i] ^= input[i];
				ECB (temp, output);
				Array.Copy (output, 0, temp, 0, BlockSizeByte);
			}
			else {
				Array.Copy (input, 0, temp2, 0, BlockSizeByte);
				ECB (input, output);
				for (int i = 0; i < BlockSizeByte; i++)
					output[i] ^= temp[i];
				Array.Copy (temp2, 0, temp, 0, BlockSizeByte);
			}
		}
		
		// Cipher-FeedBack (CFB)
		protected virtual void CFB (byte[] input, byte[] output) {
			if (encrypt) {
				for (int x = 0; x < FeedBackIter; x++) {
					// temp is first initialized with the IV
					ECB(temp, temp2);
					for (int i = 0; i < FeedBackByte; i++)
						output[i + x] = (byte)(temp2[i] ^ input[i + x]);
					Array.Copy(temp, FeedBackByte, temp, 0, BlockSizeByte - FeedBackByte);
					Array.Copy(output, x, temp, BlockSizeByte - FeedBackByte, FeedBackByte);
				}
			} else {
				for (int x = 0; x < FeedBackIter; x++) {
					// we do not really decrypt this data!
					encrypt = true;
					// temp is first initialized with the IV
					ECB(temp, temp2);
					encrypt = false;
					
					for (int i = 0; i < FeedBackByte; i++)
						output[i + x] = (byte)(temp2[i] ^ input[i + x]);
					
					Array.Copy(temp, FeedBackByte, temp, 0, BlockSizeByte - FeedBackByte);
					Array.Copy(input, x, temp, BlockSizeByte - FeedBackByte, FeedBackByte);
				}
			}
		}
		
		// Output-FeedBack (OFB)
		protected virtual void OFB(byte[] input, byte[] output) {
			throw new NotImplementedException ("OFB not yet supported");
		}

		// Cipher Text Stealing (CTS)
		protected virtual void CTS(byte[] input, byte[] output) {
			throw new NotImplementedException ("CTS not yet supported");
		}

		// this method may get called MANY times so this is the one to optimize
		public virtual int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, ref byte[] outputBuffer, int outputOffset) {
			if (m_disposed)
				throw new ObjectDisposedException("Object is disposed");

			if (outputOffset + inputCount > outputBuffer.Length)
				throw new System.Security.Cryptography.CryptographicException("Insufficient output buffer size.");

			int offs = inputOffset;
			int full;

			// this way we don't do a modulo every time we're called
			// and we may save a division
			if (inputCount != BlockSizeByte) {
				
				// fill the last block with 0's. this doesn't matter for CFB
				if (((inputCount % BlockSizeByte) != 0) && ((algo.Mode == CipherMode.CFB) || (algo.Mode == CipherMode.OpenPGP_CFB))) {
					byte[] oldInputBuffer = new byte[inputCount];
					Array.Copy(inputBuffer, oldInputBuffer, inputCount);
					if (algo.Mode == CipherMode.CFB)
						inputBuffer = new byte[inputCount + (BlockSizeByte - (inputCount % BlockSizeByte))];
					else
						inputBuffer = new byte[inputCount + (BlockSizeByte - (inputCount % BlockSizeByte)) + 2];
					outputBuffer = new byte[inputBuffer.Length];
					Array.Copy(oldInputBuffer, 0, inputBuffer, 0, inputCount);
					inputCount = inputBuffer.Length;
				} else if ((inputCount % BlockSizeByte) != 0) {
					throw new System.Security.Cryptography.CryptographicException("Invalid input block size.");
				}
				
			} else
				full = 1;
			
			// OpenPGP needs some special treatment
			if (offs == 0 && algo.Mode == CipherMode.OpenPGP_CFB) {
				if (encrypt) {
					// at first we have an encrypted random block
					byte[] tmpInput = new byte[BlockSizeByte];
					byte[] tmp2Input = new byte[BlockSizeByte];
					outputBuffer = new byte[outputBuffer.Length + BlockSizeByte + 2];
					System.Security.Cryptography.RandomNumberGenerator rngIntro = System.Security.Cryptography.RandomNumberGenerator.Create();
					rngIntro.GetBytes(tmpInput);
					tmp2Input[0] = tmpInput[tmpInput.Length - 2];
					tmp2Input[1] = tmpInput[tmpInput.Length - 1];
					Transform(tmpInput, workout);
					Array.Copy(workout, 0, outputBuffer, 0, BlockSizeByte);
					outputOffset += BlockSizeByte;
					
					//now the last 2 bytes
					byte[] tmpWorkout = new byte[BlockSizeByte];
					//tmp2Input.Initialize();
					Transform(tmp2Input, tmpWorkout);
					Array.Copy(tmpWorkout, 0, outputBuffer, outputOffset, 2);
					outputOffset += 2;
					
					// Load feedback-register with c3 - c10
					Array.Copy(outputBuffer, 2, temp, 0, BlockSizeByte);
				} else {
					Array.Copy(inputBuffer, offs, workBuff, 0, BlockSizeByte);
					Transform(workBuff, workout);
					Array.Copy(workout, 0, openPGPStart, 0, BlockSizeByte);
					offs += BlockSizeByte;
					
					byte[] tmpInput = new byte[BlockSizeByte];
					tmpInput.Initialize();
					Array.Copy(inputBuffer, offs, tmpInput, 0, 2);
					Transform(tmpInput, workout);
					Array.Copy(workout, 0, openPGPStart, BlockSizeByte, 2);
					int x = openPGPStart.Length;
					if ((openPGPStart[x-1] != openPGPStart[x-3]) || (openPGPStart[x-2] != openPGPStart[x-4]))
						throw new System.Security.Cryptography.CryptographicException("Wrong Key!!");
					
					// Load feedback-register with c3 - c[BS+2]
					Array.Copy(inputBuffer, 2, temp, 0, BlockSizeByte);
					offs += 2;
					
				}
				
			}
			
			full = (inputCount - offs) / BlockSizeByte;
			
			int total = 0;
			for (int i = 0; i < full; i++) {
				Array.Copy(inputBuffer, offs, workBuff, 0, BlockSizeByte);
				Transform(workBuff, workout);
				Array.Copy (workout, 0, outputBuffer, outputOffset, BlockSizeByte);
				offs += BlockSizeByte;
				outputOffset += BlockSizeByte;
				total += BlockSizeByte;
			}
			return total;
		}
		
		private byte[] FinalEncrypt(byte [] inputBuffer, int inputOffset, int inputCount) {
			// are there still full block to process ?
			int full = (inputCount / BlockSizeByte) * BlockSizeByte;
			int rem = inputCount - full;
			int total = full;

			// we need to add an extra block if...
			// a. the last block isn't complate (partial);
			// b. the last block is complete but we use padding
			if ((rem > 0) || (algo.Padding != PaddingMode.None))
				total += BlockSizeByte;
			byte[] res = new byte [total];

			// process all blocks except the last (final) block
			while (total > BlockSizeByte) {
				TransformBlock(inputBuffer, inputOffset, BlockSizeByte, ref res, inputOffset);
				inputOffset += BlockSizeByte;
				total -= BlockSizeByte;
			}

			// now we only have a single last block to encrypt
			int padding = BlockSizeByte - rem;
			switch (algo.Padding) {
				case PaddingMode.None:
					break;
				case PaddingMode.PKCS7:
					for (int i = BlockSizeByte; --i >= (BlockSizeByte - padding);) 
						res [i] = (byte) padding;
					break;
				case PaddingMode.Zeros:
					for (int i = BlockSizeByte; --i >= (BlockSizeByte - padding);)
						res [i] = 0;
					break;
			}
			Array.Copy (inputBuffer, inputOffset, res, full, rem);

			// the last padded block will be transformed in-place
			TransformBlock(res, full, BlockSizeByte, ref res, full);
			return res;
		}

		private byte[] FinalDecrypt(byte [] inputBuffer, int inputOffset, int inputCount) {
			if ((inputCount % BlockSizeByte) > 0)
				throw new System.Security.Cryptography.CryptographicException ("Invalid input block size.");

			int total = inputCount;
			byte[] res = new byte [total];
			while (inputCount > 0) {
				TransformBlock (inputBuffer, inputOffset, BlockSizeByte, ref res, inputOffset);
				inputOffset += BlockSizeByte;
				inputCount -= BlockSizeByte;
			}

			switch (algo.Padding) {
				case PaddingMode.None:
					break;
				case PaddingMode.PKCS7:
					total -= res [total - 1];
					break;
				case PaddingMode.Zeros:
					// TODO
					break;
			}

			// return output without padding
			byte[] data = new byte [total];
			Array.Copy (res, 0, data, 0, total);
			// zeroize decrypted data (copy with padding)
			Array.Clear (res, 0, res.Length);
			return data;
		}

		public virtual byte [] TransformFinalBlock (byte [] inputBuffer, int inputOffset, int inputCount) {
			if (m_disposed)
				throw new ObjectDisposedException ("Object is disposed");

			if (encrypt)
				return FinalEncrypt (inputBuffer, inputOffset, inputCount);
			else
				return FinalDecrypt (inputBuffer, inputOffset, inputCount);
		}
	}

	/// <summary>
	/// Abstract base class for all cryptographic symmetric algorithms.
	/// Available algorithms include:
	/// DES, RC2, Rijndael, TripleDES
	/// </summary>
	public abstract class SymmetricAlgorithm : IDisposable {
		protected int BlockSizeValue; // The block size of the cryptographic operation in bits. 
		protected int FeedbackSizeValue; // The feedback size of the cryptographic operation in bits. 
		protected byte[] IVValue; // The initialization vector ( IV) for the symmetric algorithm. 
		protected int KeySizeValue; // The size of the secret key used by the symmetric algorithm in bits. 
		protected byte[] KeyValue; // The secret key for the symmetric algorithm. 
		protected KeySizes[] LegalBlockSizesValue; // Specifies the block sizes that are supported by the symmetric algorithm. 
		protected KeySizes[] LegalKeySizesValue; // Specifies the key sizes that are supported by the symmetric algorithm. 
		protected CipherMode ModeValue; // Represents the cipher mode used in the symmetric algorithm. 
		protected PaddingMode PaddingValue; // Represents the padding mode used in the symmetric algorithm. 
		private bool m_disposed;

		/// <summary>
		/// Called from constructor of derived class.
		/// </summary>
		public SymmetricAlgorithm () {
			ModeValue = CipherMode.CBC;
			PaddingValue = PaddingMode.PKCS7;
			m_disposed = false;
		}
		
		/// <summary>
		/// Called from constructor of derived class.
		/// </summary>
		~SymmetricAlgorithm () {
			Dispose (false);
		}

		public void Clear() {
			Dispose (true);
		}

		void IDisposable.Dispose () {
			Dispose (true);
			GC.SuppressFinalize (this);  // Finalization is now unnecessary
		}

		protected virtual void Dispose (bool disposing) {
			if (!m_disposed) {
				// always zeroize keys
				if (KeyValue != null) {
					// Zeroize the secret key and free
					Array.Clear (KeyValue, 0, KeyValue.Length);
					KeyValue = null;
				}
				// dispose unmanaged managed objects
				if (disposing) {
					// dispose managed objects
				}
				m_disposed = true;
			}
		}

		/// <summary>
		/// Gets or sets the actual BlockSize
		/// </summary>
		public virtual int BlockSize {
			get { return this.BlockSizeValue; }
			set {
				if (IsLegalKeySize(this.LegalBlockSizesValue, value))
					this.BlockSizeValue = value;
				else
					throw new System.Security.Cryptography.CryptographicException("block size not supported by algorithm");
			}
		}

		/// <summary>
		/// Gets or sets the actual FeedbackSize
		/// </summary>
		public virtual int FeedbackSize {
			get { return this.FeedbackSizeValue; }
			set {
				if (value > this.BlockSizeValue)
					throw new System.Security.Cryptography.CryptographicException("feedback size larger than block size");
				else
					this.FeedbackSizeValue = value;
			}
		}
		
		/// <summary>
		/// Gets or sets the actual Initial Vector
		/// </summary>
		public virtual byte[] IV {
			get {
				if (this.IVValue == null)
					GenerateIV();

				return this.IVValue;
			}
			set {
				if (value == null)
					throw new ArgumentNullException ("tried setting initial vector to null");
					
				if (value.Length * 8 != this.BlockSizeValue)
					throw new System.Security.Cryptography.CryptographicException ("IV length must match block size");
				
				this.IVValue = new byte[value.Length];
				Array.Copy (value, 0, this.IVValue, 0, value.Length);
			}
		}

		/// <summary>
		/// Gets or sets the actual key
		/// </summary>
		public virtual byte[] Key {
			get {
				if (this.KeyValue == null)
					GenerateKey();

				return this.KeyValue;
			}
			set {
				if (value == null)
					throw new ArgumentNullException ("tried setting key to null");

				if (!IsLegalKeySize (this.LegalKeySizesValue, value.Length * 8))
					throw new System.Security.Cryptography.CryptographicException ("key size not supported by algorithm");

				this.KeySizeValue = value.Length * 8;
				this.KeyValue = new byte [value.Length];
				Array.Copy (value, 0, this.KeyValue, 0, value.Length);
			}
		}
		
		/// <summary>
		/// Gets or sets the actual key size in bits
		/// </summary>
		public virtual int KeySize {
			get { return this.KeySizeValue; }
			set {
				if (!IsLegalKeySize (this.LegalKeySizesValue, value))
					throw new System.Security.Cryptography.CryptographicException ("key size not supported by algorithm");
				
				this.KeyValue = null;
				this.KeySizeValue = value;
			}
		}

		/// <summary>
		/// Gets all legal block sizes
		/// </summary>
		public virtual KeySizes[] LegalBlockSizes {
			get { return this.LegalBlockSizesValue; }
		}

		/// <summary>
		/// Gets all legal key sizes
		/// </summary>
		public virtual KeySizes[] LegalKeySizes {
			get { return this.LegalKeySizesValue; }
		}

		/// <summary>
		/// Gets or sets the actual cipher mode
		/// </summary>
		public virtual CipherMode Mode {
			get { 
				return this.ModeValue;
			}
			set {
				if (Enum.IsDefined( ModeValue.GetType (), value))
					this.ModeValue = value;
				else
					throw new System.Security.Cryptography.CryptographicException ("padding mode not available");
				
				if (value == CipherMode.OpenPGP_CFB) {
					IV = new byte[BlockSize >> 3];
					this.IVValue.Initialize();
				}
			}
		}

		/// <summary>
		/// Gets or sets the actual padding
		/// </summary>
		public virtual PaddingMode Padding {
			get { return this.PaddingValue; }
			set {
				if (Enum.IsDefined (PaddingValue.GetType (), value))
					this.PaddingValue = value;
				else
					throw new System.Security.Cryptography.CryptographicException ("padding mode not available");
			}
		}

		/// <summary>
		/// Gets an Decryptor transform object to work with a CryptoStream
		/// </summary>
		public virtual ICryptoTransform CreateDecryptor () {
			return CreateDecryptor (Key, IV);
		}

		/// <summary>
		/// Gets an Decryptor transform object to work with a CryptoStream
		/// </summary>
		public abstract ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[] rgbIV);

		/// <summary>
		/// Gets an Encryptor transform object to work with a CryptoStream
		/// </summary>
		public virtual ICryptoTransform CreateEncryptor() {
			return CreateEncryptor (Key, IV);
		}

		/// <summary>
		/// Gets an Encryptor transform object to work with a CryptoStream
		/// </summary>
		public abstract ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[] rgbIV);

		/// <summary>
		/// used to generate an inital vector if none is specified
		/// </summary>
		public abstract void GenerateIV ();

		/// <summary>
		/// used to generate a random key if none is specified
		/// </summary>
		public abstract void GenerateKey ();

		internal bool IsLegalKeySize (KeySizes[] LegalKeys, int Size) {
			foreach (KeySizes LegalKeySize in LegalKeys) {
				for (int i=LegalKeySize.MinSize; i<=LegalKeySize.MaxSize; i+=LegalKeySize.SkipSize) {
					if (i == Size)
						return true;
				}
			}
			return false;
		}
		
		/// <summary>
		/// Checks wether the given keyLength is valid for the current algorithm
		/// </summary>
		/// <param name="bitLength">the given keyLength</param>
		public bool ValidKeySize (int bitLength) {
			return IsLegalKeySize (LegalKeySizesValue, bitLength);
		}
		
		/// <summary>
		/// Creates the default implementation of the default symmetric algorithm (Rijndael).
		/// </summary>
		// LAMESPEC: Default is Rijndael - not TripleDES
		public static SymmetricAlgorithm Create () {
			return (SymmetricAlgorithm)Activator.CreateInstance(Type.GetType("SharpPrivacy.SharpPrivacyLib.Cipher.SymmetricAlgorithm"), null);
		}
		
	}
}


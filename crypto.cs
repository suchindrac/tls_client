using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;
using System.Net;
using System.Numerics;
using System.Globalization;
using common;

namespace crypto
{
	public class AES_CTR : SymmetricAlgorithm
	{
		public byte[] counter;
		public AesManaged aes;
		public int keySize = 128;
		public AES_CTR(byte[] counter, int ks)
		{
			this.keySize = ks;
			using (this.aes = new AesManaged())
			{
				this.aes.KeySize = this.keySize;
				this.aes.Mode = CipherMode.ECB;
				aes.Padding = PaddingMode.None;
			}
			
			this.counter = counter;
		}
		
		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] ignoredParamter)
		{
			return new CryptoTransform(this.aes, rgbKey, this.counter, this.keySize);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] ignoredParamter)
		{
			return new CryptoTransform(this.aes, rgbKey, this.counter, this.keySize);
		}
		
		public override void GenerateKey()
		{
			this.aes.GenerateKey();
		}

		public override void GenerateIV()
		{
			
		}
	}

	public class CryptoTransform : ICryptoTransform
	{
		public byte[] counter;
		public ICryptoTransform encryptor;
		public SymmetricAlgorithm aes;
		public Queue<byte> xorMask = new Queue<byte>();
		public int keySize = 128;

		public CryptoTransform(SymmetricAlgorithm aesAlg, byte[] key, byte[] counter, int ks)
		{
			this.keySize = ks;
			this.aes = aesAlg;
			this.counter = counter;
			byte[] zeroIv = new byte[128 / 8];
			this.encryptor = aes.CreateEncryptor(key, zeroIv);
		}
				
		public byte[] TransformFinalBlock(byte[] input, int offset, int count)
		{
			byte[] output = new byte[count];
			TransformBlock(input, offset, count, output, 0);
			return output;
		}
		public int TransformBlock(byte[] input, int offset, int count, byte[] output, int out_offset)
		{
			for (int i = 0; i < count; i ++)
			{
				if (this.xorMask.Count == 0)
				{
					EncryptCounterThenIncrement();
				}
				var mask = this.xorMask.Dequeue();
				output[out_offset +i] = (byte) (input[offset + i] ^ mask);
				
			}
			return count;
		}
		
		public void EncryptCounterThenIncrement()
		{
			byte[] block = new byte[16];
			this.encryptor.TransformBlock(this.counter, 0, this.counter.Length, block, 0);
			IncrementCounter();
			
			foreach(var b in block)
			{
				this.xorMask.Enqueue(b);
			}
		}

		public void IncrementCounter()
		{
			for (int i = this.counter.Length - 1; i >= 0; i --)
			{
				if (++this.counter[i] != 0)
				{
					break;
				}
			}
		}
		
		public int InputBlockSize { get { return this.aes.BlockSize / 8; } } 
		public int OutputBlockSize { get { return this.aes.BlockSize / 8; } } 
		public bool CanTransformMultipleBlocks { get { return true; } } 
		public bool CanReuseTransform { get { return false; } } 
				 
		public void Dispose() 
		{ 
		
		} 

	}
	public class Encryption
	{
		AES_CTR aesctr;
		ICryptoTransform ctrenc;
		Common cf;
		
		public Encryption()
		{
			
		}
		
		public CipherMode EncMode(String name)
		{
			switch(name)
			{
				case "CBC":		return CipherMode.CBC;
				case "ECB":		return CipherMode.ECB;
				default: return CipherMode.CBC;
			}
		}

		public byte[] AES_Encrypt_ECB(byte[] data, byte[] Key, int ks)
		{


			byte[] encrypted = null;
			using (RijndaelManaged aesAlg = new RijndaelManaged())
			{
				aesAlg.Mode = EncMode("ECB");
				aesAlg.Padding = PaddingMode.None;
				aesAlg.BlockSize = 128;

				aesAlg.KeySize = ks;
				aesAlg.Key = Key;

				ICryptoTransform encryptor = aesAlg.CreateEncryptor();

				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						csEncrypt.Write(data, 0, data.Length);
						csEncrypt.Flush();
						csEncrypt.Close();
						encrypted = msEncrypt.ToArray();
					}
				}
			}
			return encrypted;
		}

		public byte[] AES_Encrypt(byte[] data, byte[] Key, byte[] IV, String encMode, int ks)
		{


			byte[] encrypted = null;
			using (RijndaelManaged aesAlg = new RijndaelManaged())
			{
				aesAlg.Mode = EncMode(encMode);
				aesAlg.Padding = PaddingMode.None;
				aesAlg.BlockSize = 128;

				aesAlg.KeySize = ks;
				aesAlg.Key = Key;
				aesAlg.IV = IV;

				ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						csEncrypt.Write(data, 0, data.Length);
						csEncrypt.Flush();
						csEncrypt.Close();
						encrypted = msEncrypt.ToArray();
					}
				}
			}
			return encrypted;
		}

		public byte[] AES_Decrypt_GCM(byte[] cryptBytes, byte[] Key, byte[] IV, int ks)
		{
			byte[] iv;
			List <byte> temp = new List<byte> ();
			
			temp.AddRange(IV);
			temp.AddRange(cryptBytes.Take(8).ToArray());
			
			iv = temp.ToArray();
			
			/*
			 * The counter array (starting at 2)
			 *
			 */
			byte[] incr = BitConverter.GetBytes((int) 2);
			Array.Reverse(incr);

			/*
			 * Counter = First 4 bytes of IV + 8 Random bytes + 4 bytes of sequential value (starting at 2)
			 *
			 */

			temp.Clear();
			temp.TrimExcess();

			temp.AddRange(iv);
			temp.AddRange(incr);

			byte[] counter = temp.ToArray();

	       		this.aesctr = new AES_CTR(counter, ks);
	       		this.ctrenc = aesctr.CreateEncryptor(Key, null);
	       		byte[] output = new byte[81920];
	       		int numBytes = this.ctrenc.TransformBlock(cryptBytes.Skip(8).Take(cryptBytes.Length - 16).ToArray(), 0, cryptBytes.Length - 8 - 16, output, 0);

			return output.Take(numBytes).ToArray();		       	
		}
		/*
		 * Receiving seqNum as UInt64 and content_type as byte
		 *
		 */
		public byte[] AES_Encrypt_GCM(byte[] client_write_key, byte[] client_write_iv, byte[] plaintext, UInt64 seqNum, byte content_type, int ks, Common cf)
		{
			this.cf = cf;
			/*
			 * Calculate plaintext size to use later
			 *
			 */
		       	int plaintext_size = plaintext.Length;
		       	
		       	/*
		       	 * Initialize a temp list
		       	 *
		       	 */
		       	List<byte> temp = new List<byte>();

			/*
			 * Encrypt a block of 0's and using the key
			 *  The result will be H_client
			 *
			 */
			byte[] init_bytes = new byte[16];
		 	Array.Clear(init_bytes, 0, 16);

		 	byte[] encrypted = AES_Encrypt_ECB(init_bytes, client_write_key, ks);
			Array.Reverse(encrypted);
		 	BigInteger H_client = new BigInteger(encrypted);

			/*
			 * BigInteger class considers numbers with MSB (Most Significant Bit) set, as negative.
			 *  In such a case, an extra byte 00 is added to the number and converted back to BigInteger
			 * More details at the end of the following article:
			 *
			 * https://msdn.microsoft.com/en-us/library/system.numerics.biginteger(v=vs.110).aspx
			 */
			 
			if (H_client < 0)
			{
				temp.Clear();
				temp.TrimExcess();
				
				temp.AddRange(H_client.ToByteArray());
				temp.Add(0);
		 	
		 		H_client = new BigInteger(temp.ToArray());
			}
			
			/*
			 * Create random number to calculate IV + random
			 *  This is concatenated with a counter array and passed to AES_CTR class
			 *
			 */
			 
			Random rnd = new Random();
		       	byte[] random = new byte[8];
			rnd.NextBytes(random);
		       	
		       	/*
		       	 * The counter array (starting at 2)
		       	 *
		       	 */
		       	byte[] incr = BitConverter.GetBytes((int) 2);
		       	Array.Reverse(incr);

			/*
			 * Counter = First 4 bytes of IV + 8 Random bytes + 4 bytes of sequential value (starting at 2)
			 *
			 */

			temp.Clear();
			temp.TrimExcess();
			
		       	temp.AddRange(client_write_iv);
		       	temp.AddRange(random);
		       	
		       	byte[] iv = temp.ToArray();
		       	
		       	temp.AddRange(incr);

		       	byte[] counter = temp.ToArray();
		       	
		       	/*
		       	 * ctext == Cipher Text
		       	 *
		       	 */
		       	byte[] ctext;
		       	
		       	/*
		       	 * Plaintext is 16 bytes for Handshake message. Hence, we use TransformFinalBlock here
		       	 *
		       	 */
	       		this.aesctr = new AES_CTR(counter, ks);
	       		this.ctrenc = aesctr.CreateEncryptor(client_write_key, null);
	       		ctext = this.ctrenc.TransformFinalBlock(plaintext, 0, plaintext_size);
		 
		 	/*
		 	 * Now creating the AAD
		 	 *  AAD = Sequence Number + Content Type + TLS Version + Plaintext Size
		 	 *
		 	 */
		 	byte[] seq_num = BitConverter.GetBytes(seqNum);
			Array.Reverse(seq_num);

		 	/*
		 	 * Using UInt16 instead of short
		 	 *
		 	 */
		 	byte[] tls_version = BitConverter.GetBytes((UInt16) 771);
		 	byte[] plaintext_size_array = BitConverter.GetBytes((UInt16) plaintext_size);
		 	
		 	/*
		 	 * Size was returned as 10 00 instead of 00 10
		 	 *
		 	 */
	 		Array.Reverse(plaintext_size_array);
		 	temp.Clear();
		 	temp.TrimExcess();
		 	
		 	temp.AddRange(seq_num);
		 	temp.Add(content_type);
		 	temp.AddRange(tls_version);
		 	temp.AddRange(plaintext_size_array);
		 	
		 	byte[] auth_data = temp.ToArray();
		 	
		 	/*
		 	 * Calculating Auth Tag using GHASH function
		 	 *
		 	 */
		 	BigInteger auth_tag = GHASH(H_client, auth_data, ctext);

			/*
			 * E = ENCRYPTION(IV + "\x00\x00\x00\x01")
			 *  Auth Tag = Auth Tag ^ E
			 *
			 */
			 
		 	byte[] cval = {0, 0, 0, 1};
			temp.Clear();
			temp.TrimExcess();
			
			temp.AddRange(iv);
			temp.AddRange(cval);

			byte[] encrypted1 = AES_Encrypt_ECB(temp.ToArray(), client_write_key, ks);
			Array.Reverse(encrypted1);
			
			BigInteger nenc = new BigInteger(encrypted1);

			/*
			 * Again if nenc is less than 0, we append a byte of 00 to the end, and convert it back
			 *
			 */
			if (nenc < 0)
			{
				temp.Clear();
				temp.TrimExcess();
				
				temp.AddRange(nenc.ToByteArray());
				temp.Add(0);
				
				nenc = new BigInteger(temp.ToArray());
			}
			
		      	auth_tag ^= nenc;
		      	
		      	/*
		      	 * ToByteArray has to be inverted
		      	 *
		      	 */
		      	byte[] auth_tag_array = auth_tag.ToByteArray();
			Array.Reverse(auth_tag_array);
			
			if (auth_tag_array[0] == 0x00)
			{
				auth_tag_array = auth_tag_array.Skip(1).ToArray();
			}
			
			temp.Clear();
			temp.TrimExcess();
			
			/*
			 * Sending random + cipher text + auth_tag_array
			 *
			 */
		      	temp.AddRange(random);
		      	temp.AddRange(ctext);
		      	temp.AddRange(auth_tag_array);

		 	return temp.ToArray();
		}
		
		public BigInteger GF_mult(BigInteger x, BigInteger y)
		{
			BigInteger product = new BigInteger(0);
			BigInteger e10 = BigInteger.Parse("00E1000000000000000000000000000000", NumberStyles.AllowHexSpecifier);

			/*
			 * Below operation y >> i fails if i is UInt32, so leaving it as int
			 *
			 */
			int i = 127;
			while (i != -1)
			{
				product = product ^ (x * ((y >> i) & 1));
				x = (x >> 1) ^ ((x & 1) * e10);
				i = i - 1;
			}
			
			return product;
		}
		
		public BigInteger H_mult(BigInteger H, BigInteger val)
		{
			BigInteger product = new BigInteger(0);
			int i = 0;

			/*
			 * Below operation (val & 0xFF) << (8 * i) fails if i is UInt32, so leaving it as int
			 *
			 */

			while (i < 16)
			{
				product = product ^ GF_mult(H, (val & 0xFF) << (8 * i));
				val = val >> 8;
				i = i + 1;	
			}
			return product;
		}
		
		public BigInteger GHASH(BigInteger H, byte[] A, byte[] C)
		{
			int C_len = C.Length;
			List <byte> temp = new List<byte>();
			
			int plen = 16 - (A.Length % 16);
			byte[] zeroes = new byte[plen];
			Array.Clear(zeroes, 0, zeroes.Length);
			
			temp.AddRange(A);
			temp.AddRange(zeroes);
			temp.Reverse();
			
			BigInteger A_padded = new BigInteger(temp.ToArray());
			
			temp.Clear();
			temp.TrimExcess();
			
			byte[] C1;
			
			if ((C_len % 16) != 0)
			{
				plen = 16 - (C_len % 16);
				byte[] zeroes1 = new byte[plen];
				Array.Clear(zeroes, 0, zeroes.Length);
				
				temp.AddRange(C);
				temp.AddRange(zeroes1);
				C1 = temp.ToArray();
			}
			else
			{
				C1 = new byte[C.Length];
				Array.Copy(C, 0, C1, 0, C.Length);
			}

						
			temp.Clear();
			temp.TrimExcess();
			
			BigInteger tag = new BigInteger();
			
			tag = H_mult(H, A_padded);
			
			for (int i = 0; i < (int) (C1.Length / 16); i ++)
			{
				byte[] toTake;
				if (i == 0)
				{
					toTake = C1.Take(16).ToArray();
				}
				else
				{
					toTake = C1.Skip(i * 16).Take(16).ToArray();
				}
				Array.Reverse(toTake);
				BigInteger tempNum = new BigInteger(toTake);
				tag ^= tempNum;
				tag = H_mult(H, tag);
			}

			
			byte[] A_arr = BitConverter.GetBytes((long) (8 * A.Length));
			/*
			 * Want length to be "00 00 00 00 00 00 00 xy" format
			 *
			 */
			Array.Reverse(A_arr);

			byte[] C_arr = BitConverter.GetBytes((long) (8 * C_len));
			/*
			 * Want length to be "00 00 00 00 00 00 00 xy" format
			 *
			 */
			Array.Reverse(C_arr);
			
			temp.AddRange(A_arr);
			temp.AddRange(C_arr);
			temp.Reverse();
			
			BigInteger array_int = new BigInteger(temp.ToArray());

			tag = tag ^ array_int;
			
			tag = H_mult(H, tag);

			return tag;
		}
		
		public byte[] AES_Decrypt(byte[] cryptBytes, byte[] Key, byte[] IV, String encMode, int ks)
		{
			byte[] clearBytes = null;
			
			using (RijndaelManaged aes = new RijndaelManaged())
 			{
 				aes.KeySize = ks;
				aes.Key = Key;
				aes.IV = IV;
				aes.Padding = PaddingMode.None;

        			using (MemoryStream ms = new MemoryStream())
 				{
					using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
 					{
						cs.Write(cryptBytes, 0, cryptBytes.Length);
						cs.Flush();
						cs.Close();
 					}
					clearBytes = ms.ToArray();
				}
			}
			return clearBytes;
		}		
	}
	
	public class CipherProps
	{
		public int cipher;
		public String protocol;
		public String key_exch_alg;
		public String sig_alg;
		public String enc_alg;
		public int key_size;
		public String enc_mode;
		public String hash_alg;

		public CipherProps(int cVal, String proto, String kxAlg, String sigAlg, String encAlg, int kSize, String encMode, String hAlg)
		{
			this.cipher = cVal;
			this.protocol = proto;
			this.key_exch_alg = kxAlg;
			this.sig_alg = sigAlg;
			this.enc_alg = encAlg;
			this.key_size = kSize;
			this.enc_mode = encMode;
			this.hash_alg = hAlg;
		}
	}

	public class Cipher
	{
		public ushort cipher_suite;
		public Dictionary <int, String> cipher_names = new Dictionary <int, String> ();

		public int macSize;
		public int keySize;
		public int ivSize;
		public int prfHmacSize;

		List <CipherProps> cprops_list;
		bool supported;
		public CipherProps cprops;
		public String cipher_name;

		public Cipher(ushort csuite)
		{
			this.cipher_suite = csuite;
			this.cipher_names.Add(0x2f, "TLS_RSA_WITH_AES_128_CBC_SHA");
			this.cipher_names.Add(0x35, "TLS_RSA_WITH_AES_256_CBC_SHA");
			this.cipher_names.Add(0x3c, "TLS_RSA_WITH_AES_128_CBC_SHA256");
			this.cipher_names.Add(0x3d, "TLS_RSA_WITH_AES_256_CBC_SHA256");
			this.cipher_names.Add(0x9c, "TLS_RSA_WITH_AES_128_GCM_SHA256");
			this.cipher_names.Add(0x9d, "TLS_RSA_WITH_AES_256_GCM_SHA384");
			this.cipher_names.Add(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
			this.cipher_names.Add(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
			

			if (this.cipher_suite == 0xc013)
			{
				this.macSize = 20;
				this.keySize = 16;
				this.ivSize = 16;
				this.prfHmacSize = 256;
			}
			
			if (this.cipher_suite == 0x2f)
			{
				this.macSize = 20;
				this.keySize = 16;
				this.ivSize = 16;
				this.prfHmacSize = 256;
			}
			else if (this.cipher_suite == 0x35)
			{
				this.macSize = 20;
				this.keySize = 32;
				this.ivSize = 16;
				this.prfHmacSize = 256;
			}
			else if (this.cipher_suite == 0x3c)
			{
				this.macSize = 32;
				this.keySize = 16;
				this.ivSize = 16;
				this.prfHmacSize = 256;				
			}
			else if (this.cipher_suite == 0x3d)
			{
				this.macSize = 32;
				this.keySize = 32;
				this.ivSize = 16;
				this.prfHmacSize = 256;				
			}

			if (this.cipher_suite == 0x9c)
			{
				this.macSize = 0;
				this.keySize = 16;
				this.ivSize = 4;
				this.prfHmacSize = 256;				
			}

			if (this.cipher_suite == 0x9d)
			{
				this.macSize = 0;
				this.keySize = 32;
				this.ivSize = 4;
				this.prfHmacSize = 384;				
			}

			if (this.cipher_suite == 0xc02f)
			{
				this.macSize = 0;
				this.keySize = 16;
				this.ivSize = 4;
				this.prfHmacSize = 256;				
			}

			this.cprops_list = new List<CipherProps>();
			this.supported = Supported();
			foreach(int key in this.cipher_names.Keys)
			{
				String name = this.cipher_names[key];
				name = name.Replace("WITH_", "");
				String[] nameParts = name.Split('_');
				if (nameParts.Length == 6)
				{
					CipherProps c = new CipherProps(key, nameParts[0], nameParts[1], (String) "NONE", nameParts[2], 
							Convert.ToInt32(nameParts[3]), nameParts[4], nameParts[5]);
					this.cprops_list.Add(c);
					if (key == this.cipher_suite)
					{
						this.cprops = c;
						this.cipher_name = name;
					}
				} else if (nameParts.Length == 7)
				{
					CipherProps c = new CipherProps(key, nameParts[0], nameParts[1], nameParts[2], nameParts[3],
							Convert.ToInt32(nameParts[4]), nameParts[5], nameParts[6]);
					this.cprops_list.Add(c);
					if (key == this.cipher_suite)
					{
						this.cprops = c;
						this.cipher_name = name;
					}
				}
			}

		}

		public bool Supported()
		{
			if (this.cipher_names.ContainsKey(this.cipher_suite))
			{
				return true;
			}
			else
			{
				return false;
			}

		}

		public String GetEncAlg()
		{
			return this.cprops.enc_alg;
		}

		public int GetKeySize()
		{
			return this.cprops.key_size;
		}

		public String GetHmacAlg()
		{
			return "HMAC" + this.cprops.hash_alg;
		}

		public String GetKeyExchAlg()
		{
			return this.cprops.key_exch_alg;
		}

		public String GetProtocol()
		{
			return this.cprops.protocol;
		}
		
		public String GetSigAlg()
		{
			return this.cprops.sig_alg;
		}

		public String GetEncMode()
		{
			return this.cprops.enc_mode;
		}
	}
}
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

namespace handshake
{
	public class ClientKeyExchange
	{
		byte majorVersion;
		byte minorVersion;
		List <byte> ckeMessage;
		byte[] sCert_hs;
		List <byte> pre_master_secret_list;
		byte[] pre_master_secret;
		public ECDiffieHellmanPublicKey pre_master_secret_key;
		public ECDiffieHellmanCng ecdhCngClient;
		
		byte[] sKeyExch_hs;
		public byte[] client_pub_key_bytes;
		
		public byte[] client_pub_key_to_server;
		public ECDiffieHellmanPublicKey server_pub_key;
		public ECDiffieHellmanPublicKey client_pub_key;
		
		
		String kxType;

		Common common;
		
		public ClientKeyExchange(Common cf, byte[] sCert_hs, byte major, byte minor, byte[] ske, String kxtp)
		{
			this.common = cf;
			this.majorVersion = major;
			this.minorVersion = minor;
			this.sCert_hs = sCert_hs;
			this.sKeyExch_hs = ske;
			
			
			this.kxType = kxtp;
			this.pre_master_secret_list = new List<byte>();
		}
		
		private UInt16 KeySizeToNamedCurve(int keySize)
		{
		switch (keySize) {
			case 256:
				// NamedCurve.secp256r1
				return 23;
			case 384:
				// NamedCurve.secp384r1
				return 24;
			case 521:
				// NamedCurve.secp521r1
				return 25;
			default:
				throw new Exception("Unsupported ECDH key size: " + keySize);
		}
		}
		private int NamedCurveToKeySize(UInt16 namedCurve)
		{
			switch (namedCurve) {
				case 23:
					return 256;
				case 24:
					return 384;
				case 25:
					return 521;
				default:
					throw new Exception("Unsupported NamedCurve: " + namedCurve);
			}
		}
		
		public List<byte> CreateCKE()
		{

			if (this.kxType == "RSA")
			{
				List<byte> protocolVersion = new List<byte> ();
				List<byte> preMasterSecret = new List<byte>();

				byte[] random;
				Random rnd;

				protocolVersion.Add(this.majorVersion);
				protocolVersion.Add(this.minorVersion);

				random = new byte[46];
				rnd = new Random();
				rnd.NextBytes(random);

				preMasterSecret.AddRange(protocolVersion.ToArray());
				preMasterSecret.AddRange(random);

				this.pre_master_secret_list = preMasterSecret;
				this.pre_master_secret = preMasterSecret.ToArray();

				int certLen = this.common.ReadAtLoc(this.sCert_hs, 7, 3);

				byte[] sCert = new byte[certLen];
				Array.Copy(this.sCert_hs, 10, sCert, 0, certLen);

				String b64Cert = Convert.ToBase64String(sCert);

				System.IO.File.WriteAllText(@"server_cert.pem", b64Cert);
				X509Certificate2 cert = new X509Certificate2(sCert);
				byte[] publicKey = cert.PublicKey.EncodedKeyValue.RawData;
				String b64PubKey = Convert.ToBase64String(publicKey);

				RSACryptoServiceProvider rsaProvider = (RSACryptoServiceProvider) cert.PublicKey.Key;

				byte[] encPMKey = rsaProvider.Encrypt(this.pre_master_secret, RSAEncryptionPadding.Pkcs1);
				byte[] encPMKey_len = BitConverter.GetBytes((short) encPMKey.Length);
				Array.Reverse(encPMKey_len);

				this.ckeMessage = new List<byte>();
				this.ckeMessage.AddRange(encPMKey_len);
				this.ckeMessage.AddRange(encPMKey);

				return this.ckeMessage;
			}
			else if(this.kxType == "ECDHE")
			{
				int skeLen = this.sKeyExch_hs[7];
				skeLen = skeLen - 1;

				byte[] sPubKey = new byte[skeLen];
				Buffer.BlockCopy(this.sKeyExch_hs, 9, sPubKey, 0, skeLen);
				
				this.ecdhCngClient = new ECDiffieHellmanCng(256);
				
				this.client_pub_key = this.ecdhCngClient.PublicKey;
				
				this.client_pub_key_bytes = this.ecdhCngClient.PublicKey.ToByteArray();

				byte[] i = {0x04};

				this.client_pub_key_bytes = this.client_pub_key_bytes.Skip(8).ToArray();

				this.client_pub_key_bytes = i.Concat(this.client_pub_key_bytes).ToArray();

				byte[] x = {0x45, 0x43, 0x4B, 0x31, 0x20, 0, 0, 0};
				
				sPubKey = x.Concat(sPubKey).ToArray();

				ECDiffieHellmanPublicKey serverKey = ECDiffieHellmanCngPublicKey.FromByteArray(sPubKey, CngKeyBlobFormat.EccPublicBlob);
				
				this.server_pub_key = serverKey;
				
				byte[] symmKey = this.ecdhCngClient.DeriveKeyMaterial(serverKey);
				
				this.pre_master_secret = sPubKey;
				
				this.pre_master_secret_list = new List<byte>(this.pre_master_secret);
				
				byte client_pub_key_len = (byte) this.client_pub_key_bytes.Length;
				
				this.ckeMessage = new List<byte>();
				this.ckeMessage.Add(client_pub_key_len);
				this.ckeMessage.AddRange(this.client_pub_key_bytes);
				
				return this.ckeMessage;
			}
			List <byte> result1 = new List<byte>();
			return result1;
		}
		
		public List<byte> GetPremasterSecret()
		{
			return this.pre_master_secret_list;
		}
	}


	public class ClientHello
	{
		byte majorVersion;
		byte minorVersion;
		bool gen_session_id;

		UInt32 gmt_unix_time;
		byte[] random_bytes = new byte[28];
		byte session_id_len;
		byte[] session_id;

		String clientIP_str;
		String serverIP_str;
		
		List<byte> client_random_list;
		
		byte[] cipher_suites;

		byte compression_methods_len;
		byte[] compression_methods;

		short extensions_len;
		byte[] extensions;

		List<byte> clientHello = new List<byte>();

		public ClientHello(String clientIP_str, String serverIP_str, byte major, byte minor, bool gen_sid, List<UInt32> csuites)
		{
			this.majorVersion = major;
			this.minorVersion = minor;
			this.gen_session_id = gen_sid;
			this.clientIP_str = clientIP_str;
			this.serverIP_str = serverIP_str;
			
			List <byte> cipher_suites_blist = new List<byte>();

			foreach (short cipher_suite in csuites)
			{
				cipher_suites_blist.AddRange(BitConverter.GetBytes(cipher_suite));
			}


			this.cipher_suites = cipher_suites_blist.ToArray();
			Array.Reverse(this.cipher_suites);
		}

		public static UInt32 ReverseBytes(UInt32 value)
		{
		     return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
			 (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
		}

		public List<byte> Get()
		{
			List<byte> client_version = new List<byte>();
			client_version.Add(this.majorVersion);
			client_version.Add(this.minorVersion);

			TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
			this.gmt_unix_time = ReverseBytes((UInt32) t.TotalSeconds);

			Random rnd = new Random();
			rnd.NextBytes(this.random_bytes);

			if (this.gen_session_id)
			{
				this.session_id_len = 32;
				this.session_id = new byte[32];
				rnd.NextBytes(this.session_id);
			}
			else
			{
				this.session_id_len = 0;
			}

			this.compression_methods_len = 0x1;
			this.compression_methods = new byte[this.compression_methods_len];
			this.compression_methods[0] = 0x0;

			this.extensions_len = 68;

			List <byte> extensions_list = new List<byte> ();

			byte[] extType  = BitConverter.GetBytes((short) 26);
			Array.Reverse(extType);

			byte[] sharedRandom = new byte[16];
			rnd.NextBytes(sharedRandom);


			byte[] clientIP_bytes = Encoding.ASCII.GetBytes(this.clientIP_str);
			byte[] serverIP_bytes = Encoding.ASCII.GetBytes(this.serverIP_str);

			byte[] data1 = new byte[sharedRandom.Length];
			byte[] data2 = new byte[clientIP_bytes.Length];
			byte[] data3 = new byte[serverIP_bytes.Length];

			Array.Copy(sharedRandom, 0, data1, 0, sharedRandom.Length);
			Array.Copy(clientIP_bytes, 0, data2, 0, clientIP_bytes.Length);
			Array.Copy(serverIP_bytes, 0, data3, 0, serverIP_bytes.Length);

			SHA256 sha256 = SHA256.Create();

			sha256.TransformBlock(data1, 0, data1.Length, data1, 0);
			sha256.TransformBlock(data2, 0, data2.Length, data2, 0);
			sha256.TransformFinalBlock(data3, 0, data3.Length);				

			byte[] extData = new byte[sha256.HashSize/8];
			Buffer.BlockCopy(sha256.Hash, 0, extData, 0, sha256.HashSize / 8);

			byte[] extLength = BitConverter.GetBytes((short) extData.Length);
			Array.Reverse(extLength);				

			extensions_list.AddRange(extType);
			extensions_list.AddRange(extLength);
			extensions_list.AddRange(extData);

			this.extensions = extensions_list.ToArray();

			this.extensions_len = (short) (this.extensions.Length);

			this.client_random_list = new List<byte>();

			this.client_random_list.AddRange(BitConverter.GetBytes(this.gmt_unix_time));
			this.client_random_list.AddRange(this.random_bytes);

			this.clientHello.AddRange(client_version.ToArray());
			this.clientHello.AddRange(BitConverter.GetBytes(this.gmt_unix_time));
			this.clientHello.AddRange(this.random_bytes);
			if (this.gen_session_id)
			{
				this.clientHello.Add(this.session_id_len);
				this.clientHello.AddRange(this.session_id);
			}
			else
			{
				this.clientHello.Add(this.session_id_len);
			}

			byte[] cs_len = BitConverter.GetBytes((short) this.cipher_suites.Length);
			Array.Reverse(cs_len);

			this.clientHello.AddRange(cs_len);
			this.clientHello.AddRange(this.cipher_suites);

			this.clientHello.Add(this.compression_methods_len);
			this.clientHello.AddRange(this.compression_methods);

			byte[] extlen = BitConverter.GetBytes(this.extensions_len);
			Array.Reverse(extlen);
			this.clientHello.AddRange(extlen);
			this.clientHello.AddRange(this.extensions);
			return this.clientHello;
		}
		public List<byte> GetRandom()
		{
			
			return this.client_random_list;
		}
	}
}
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
using common;
using handshake;
using crypto;

namespace SecureClient
{
	public class LibTLSClient
	{
		Common common;
		Encryption enc;
		public List<byte> all_hs_msgs;
		public byte[] temp;
		public byte[] temp2;
		public byte[] temp3;
		public byte[] temp4;

		public int errorCode;
		public short recLen;
		public short hsLen;

		public List<byte> hsBuf;
		public List<byte> recBuf; 
		public List<byte> pktBuf;
		public byte[] serverResp;
		public NetworkStream ns;
		public TcpClient client;
		public TLSHandshake hs;
		public TLSRecord rec;
		public int tmp;
		public int lastBytesRead;
		public int bytesProcessed = 0;
		public UInt32 cipher = 0xc02f;
		public UInt32 timeout = 2000;

		public byte[] verify_data;
		public List<byte> master_secret_list;
		public List<byte> pre_master_secret_list;
		public List <byte> client_random_list;
		public List <byte> server_random_list;
		public byte[] master_secret;
		public byte[] pre_master_secret;
		public ECDiffieHellmanPublicKey pre_master_secret_key;
		public ECDiffieHellmanPublicKey server_pub_key;
		public ECDiffieHellmanPublicKey client_pub_key;
		
		public byte[] serverEncResp;
		public byte[] client_random;
		public byte[] server_random;
		public byte[] key_material;
		public byte[] client_write_MAC_secret;
		public byte[] server_write_MAC_secret;
		public byte[] client_write_key;
		public byte[] server_write_key;
		public byte[] client_write_IV;
		public byte[] server_write_IV;
		
		public byte[] cHello_hs;
		public byte[] sHello_hs;
		public byte[] sKeyExch_hs;
		public byte[] sCert_hs;
		public byte[] sHelloDone_hs;
		public byte[] cke_hs;
		public byte[] css_hs;
		public byte[] cFinished;
		
		public Cipher cipherObj;
		
		public String serverIP;
		public Exception sendExcp;
		public int debug;
		public ECDiffieHellmanCng ecdhc;
		
		public enum HSType
		{
			ClientHello,
			ServerHello,
			ServerCert,
			ServerHelloDone,
			ClientKeyExchange,
			ChangeCipherSpec,
			ClientFinished,
			ServerFinished
		}
		
		public LibTLSClient(Common cf, Encryption e)
		{
			this.common = cf;
			this.enc = e;
		}
		
		public string GetIPAddress()
		{
		
		    	IPHostEntry Host = default(IPHostEntry);
		    	string Hostname = null;
		    	string ipAddress_str = null;
		    	Hostname = System.Environment.MachineName;
		    	Host = Dns.GetHostEntry(Hostname);
		    	foreach (IPAddress IP in Host.AddressList) {
				if (IP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
				    	ipAddress_str = Convert.ToString(IP);
				}
		    	}
		    	return ipAddress_str;
		}

		
		public class ENCTLSRecord
		{
			byte[] record;
			byte[] record_len;
			byte[] seqNum;
			UInt64 seqNum_UInt;
			LibTLSClient cssl;
			public bool handshake = true;
			byte[] mac;
			byte major;
			byte minor;
			List<byte> padding_list;
			byte[] padding;
			byte[] finalPacket;
			byte[] encHS;
			byte[] encRec;
			byte[] R = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
			
			public ENCTLSRecord(byte[] hsMsg, UInt64 seq, byte major, byte minor, LibTLSClient cSSL)
			{
				this.seqNum_UInt = seq;
				this.seqNum = BitConverter.GetBytes(seq);
				Array.Reverse(this.seqNum);
				this.record = new byte[hsMsg.Length];
				Array.Copy(hsMsg, 0, this.record, 0, hsMsg.Length);
				this.record_len = BitConverter.GetBytes((short) hsMsg.Length);
				Array.Reverse(this.record_len);
				this.cssl = cSSL;
				this.major = major;
				this.minor = minor;
			}
			
			public void SetHS(bool h)
			{
				this.handshake = h;
			}
			public byte[] GetBytes()
			{
				int curLen = 0;
				List <byte> temp = new List<byte>();

				if (this.cssl.cipherObj.GetEncMode() == "CBC")
				{
					String macAlg = this.cssl.cipherObj.GetHmacAlg();
					HMAC hashObj = this.cssl.GetHmacObj(macAlg, this.cssl.client_write_MAC_secret);

					byte[] hs1 = new byte[this.seqNum.Length];
					byte[] hs2 = new byte[1];
					byte[] hs3 = new byte[1];
					byte[] hs4 = new byte[1];
					byte[] hs5 = new byte[this.record_len.Length];
					byte[] hs6 = new byte[this.record.Length];

					Array.Copy(this.seqNum, 0, hs1, 0, this.seqNum.Length);
					if (this.handshake)
					{
						hs2[0] = 22;
					}
					else
					{
						hs2[0] = 23;
					}
					hs3[0] = this.major;
					hs4[0] = this.minor;
					Array.Copy(this.record_len, 0, hs5, 0, this.record_len.Length);
					Array.Copy(this.record, 0, hs6, 0, this.record.Length);

					hashObj.TransformBlock(hs1, 0, hs1.Length, hs1, 0);
					hashObj.TransformBlock(hs2, 0, hs2.Length, hs2, 0);
					hashObj.TransformBlock(hs3, 0, hs3.Length, hs3, 0);
					hashObj.TransformBlock(hs4, 0, hs4.Length, hs4, 0);
					hashObj.TransformBlock(hs5, 0, hs5.Length, hs5, 0);
					hashObj.TransformFinalBlock(hs6, 0, hs6.Length);

					this.mac = new byte[hashObj.HashSize/8];
					Array.Copy(hashObj.Hash, 0, this.mac, 0, hashObj.Hash.Length);

					curLen = this.record.Length + this.mac.Length + 1;
					int blockLen;
					if (this.handshake)
					{
						blockLen = 16;
					}
					else
					{
						blockLen = this.cssl.client_write_IV.Length;
					}
					int padLen = blockLen - (curLen % blockLen);
					if (padLen == blockLen)
					{
						padLen = 0;
					}

					if (padLen != 0)
					{
						this.padding_list = new List<byte>();

						for (int i = 0; i < padLen + 1; i++)
						{
							this.padding_list.Add((byte) padLen);
						}
						this.padding = this.padding_list.ToArray();
					}

					temp.AddRange(this.R);
					temp.AddRange(this.record);
					temp.AddRange(this.mac);

					if (padLen != 0)
					{
						temp.AddRange(this.padding);
					}
					this.finalPacket = new byte[temp.Count];
					Array.Copy(temp.ToArray(), 0, this.finalPacket, 0, temp.Count);

					this.encHS = this.cssl.enc.AES_Encrypt(this.finalPacket, this.cssl.client_write_key, this.cssl.client_write_IV, 
				                                       this.cssl.cipherObj.GetEncMode(), this.cssl.cipherObj.GetKeySize());
				                                       
				} else if (this.cssl.cipherObj.GetEncMode() == "GCM")
				{
					UInt64 seqNum = 0L;
					byte ctype;
					if (this.handshake)
					{
						ctype = 22;
					}
					else
					{
						ctype = 23;
					}
					int ks = this.cssl.cipherObj.GetKeySize();
					this.cssl.common.pythonFormat = 1;
					this.encHS = this.cssl.enc.AES_Encrypt_GCM(this.cssl.client_write_key, this.cssl.client_write_IV, this.record, seqNum_UInt, ctype, ks, this.cssl.common);
					this.cssl.common.pythonFormat = 0;
				}
				
				temp.Clear();
				temp.TrimExcess();
				if (this.handshake)
				{
					temp.Add((byte) 22);
				}
				else
				{
					temp.Add((byte) 23);
				}
				temp.Add(this.major);
				temp.Add(this.minor);
				
				byte[] encLen = BitConverter.GetBytes((short) this.encHS.Length);
				
				Array.Reverse(encLen);
				temp.AddRange(encLen);
				temp.AddRange(this.encHS);
				
				this.encRec = temp.ToArray();
				
				return this.encRec;
			}
		}

		public byte[] DecryptResp()
		{
			byte[] dataWoInitBytes = new byte[2];
			if (this.cipherObj.GetEncMode() != "GCM")
			{
			
				byte[] decryptedData = this.enc.AES_Decrypt(this.serverEncResp, this.server_write_key, this.server_write_IV, 
			                         this.cipherObj.GetEncMode(), this.cipherObj.GetKeySize());
				byte last_byte = decryptedData[decryptedData.Length - 1];
				int iter = decryptedData.Length - 1;

				while (decryptedData[iter] == last_byte)
				{
					iter = iter - 1;
				}

				byte[] dataWoPadding = new byte[iter + 1];
				Array.Copy(decryptedData, 0, dataWoPadding, 0, iter + 1);

				int len_wo_mac = dataWoPadding.Length - this.cipherObj.macSize;
				byte[] dataWoMac = new byte[len_wo_mac];
				Array.Copy(dataWoPadding, 0, dataWoMac, 0, len_wo_mac);

				dataWoInitBytes = new byte[dataWoMac.Length - 16];
				Array.Copy(dataWoMac, 16, dataWoInitBytes, 0, dataWoMac.Length - 16);
			}
			else
			{
				byte[] decryptedData = this.enc.AES_Decrypt_GCM(this.serverEncResp, this.server_write_key, this.server_write_IV, this.cipherObj.GetKeySize());
				return decryptedData;
			}
			return dataWoInitBytes;
		}
		public class TLSRecord
		{
			byte rec_type;
			byte[] rec_version;
			byte[] rec_length;
			byte[] rec_value;
			List<byte> rec_pkt = new List<byte>();
			
			public TLSRecord(byte type, short version, short lngth, byte[] vlue)
			{
				this.rec_type = type;
				this.rec_version = BitConverter.GetBytes(version);
				Array.Reverse(this.rec_version);
				this.rec_length = BitConverter.GetBytes(lngth);
				Array.Reverse(this.rec_length);
				this.rec_value = vlue;
			}
			public List<byte> GetBytes()
			{
				this.rec_pkt.Add(this.rec_type);
				this.rec_pkt.AddRange(this.rec_version);
				this.rec_pkt.AddRange(this.rec_length);
				this.rec_pkt.AddRange(this.rec_value);
				return this.rec_pkt;
			}
		}
		
		public void ComputeVerifyData()
		{
			byte[] label = Encoding.ASCII.GetBytes("client finished");
			
			HashAlgorithm hAlg = null;
			
			if (this.cipherObj.prfHmacSize == 256)
			{
				hAlg = SHA256.Create();
			} else if (this.cipherObj.prfHmacSize == 384)
			{
				hAlg = SHA384.Create();
			}
			
			hAlg.TransformBlock(this.cHello_hs, 0, this.cHello_hs.Length, this.cHello_hs, 0);
			hAlg.TransformBlock(this.sHello_hs, 0, this.sHello_hs.Length, this.sHello_hs, 0);
			hAlg.TransformBlock(this.sCert_hs, 0, this.sCert_hs.Length, this.sCert_hs, 0);
			if (this.sKeyExch_hs != null)
			{
				hAlg.TransformBlock(this.sKeyExch_hs, 0, this.sKeyExch_hs.Length, this.sKeyExch_hs, 0);
			}
			hAlg.TransformBlock(this.sHelloDone_hs, 0, this.sHelloDone_hs.Length, this.sHelloDone_hs, 0);
			hAlg.TransformFinalBlock(this.cke_hs, 0, this.cke_hs.Length);

			byte[] seed_1_2 = new byte[hAlg.HashSize/8];

			Buffer.BlockCopy(hAlg.Hash, 0, seed_1_2, 0, hAlg.HashSize / 8);

			this.verify_data = this.PRF1(this.master_secret, label, seed_1_2, 12, this.cipherObj.prfHmacSize);
		}
		
		public void ComputeMasterSecret()
		{
			byte[] label = Encoding.ASCII.GetBytes("master secret");

			this.client_random = this.client_random_list.ToArray();
			this.server_random = this.server_random_list.ToArray();

			byte[] seed = new byte[this.client_random.Length + this.server_random.Length];

			Buffer.BlockCopy(this.client_random, 0, seed, 0, this.client_random.Length);
			Buffer.BlockCopy(this.server_random, 0, seed, this.client_random.Length, this.server_random.Length);

			this.master_secret = this.PRF1(this.pre_master_secret, label, seed, 48, this.cipherObj.prfHmacSize);
		}
		
		public void ComputeKeys()
		{
		        byte[] label = Encoding.ASCII.GetBytes("key expansion");
		
			List <byte> seedList = new List<byte>();
			seedList.AddRange(this.server_random);
			seedList.AddRange(this.client_random);
			
			int macSize = this.cipherObj.macSize;
			int keySize = this.cipherObj.keySize;
			int ivSize = this.cipherObj.ivSize;
			
			
			this.key_material = this.PRF1(this.master_secret, label, seedList.ToArray(), (macSize * 2) + (keySize * 2) + (ivSize * 2), this.cipherObj.prfHmacSize);

			if (macSize != 0)
			{
				this.client_write_MAC_secret = new byte[macSize];
				Buffer.BlockCopy(key_material, 0, this.client_write_MAC_secret, 0, macSize);
				this.server_write_MAC_secret = new byte[macSize];
				Buffer.BlockCopy(key_material, macSize, this.server_write_MAC_secret, 0, macSize);
			}
			this.client_write_key = new byte[keySize];
			Buffer.BlockCopy(key_material, macSize * 2, this.client_write_key, 0, keySize);
			this.server_write_key = new byte[keySize];
			Buffer.BlockCopy(key_material, (macSize * 2) + keySize, this.server_write_key, 0, keySize);
			this.client_write_IV = new byte[ivSize];
			Buffer.BlockCopy(key_material, (macSize * 2) + (keySize * 2), this.client_write_IV, 0, ivSize);
			this.server_write_IV = new byte[ivSize];
			Buffer.BlockCopy(key_material, (macSize * 2) + (keySize * 2) + ivSize, this.server_write_IV, 0, ivSize);
		}
		
		public byte[] PRF1(byte[] secret, byte[] label, byte[] seed, int reqLength, int hmacLength)
		{
			System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			List<byte> tempArray = new List<byte>();
			tempArray.AddRange(label);
			tempArray.AddRange(seed);
			
			byte[] pHash1 = this.P_Hash1(secret, tempArray.ToArray(), reqLength, hmacLength);
			return pHash1;
		}
		
		public HMAC GetHmacObj(String name, byte[] secret)
		{
			switch(name)
			{
				case "HMACSHA256":	return new HMACSHA256(secret);
				case "HMACSHA1":	return new HMACSHA1(secret);
				case "HMACSHA":		return new HMACSHA1(secret);
				case "HMACSHA384":	return new HMACSHA384(secret);
				case "HMACSHA512":	return new HMACSHA512(secret);
				default: return new HMACSHA256(secret);
			}
		}


		public byte[] P_Hash1(byte[] secret, byte[] seed, int reqLength, int hmacLength)
		{
			List <byte> data = new List<byte>();
			HMAC HMAC_hash_A = null;
			HMAC HMAC_hash_H = null;
			
			List<byte> A0 = new List<byte>();
			A0.AddRange(seed);
			
			List <byte> temp = new List<byte>();
			
			int i = 1;
			String msg;
			List<byte> A = new List<byte>();
			List<byte> H = new List<byte>();
			
			String className = "HMACSHA" + hmacLength.ToString();

			HMAC_hash_A = this.GetHmacObj(className, secret);
			HMAC_hash_H = this.GetHmacObj(className, secret);
			do
			{
				if (HMAC_hash_A != null)
				{
					HMAC_hash_A = this.GetHmacObj(className, secret);
				}
				
				HMAC_hash_A.ComputeHash(A0.ToArray());
				A.Clear();
				A.TrimExcess();
				A.AddRange(HMAC_hash_A.Hash);
				
		        	msg = "A(" + i.ToString() + ")";
				
				temp.Clear();
				temp.TrimExcess();
				temp.AddRange(A.ToArray());
				temp.AddRange(seed);

				if (HMAC_hash_A != null)
				{
					HMAC_hash_H = this.GetHmacObj(className, secret);
				}
				
				HMAC_hash_H.ComputeHash(temp.ToArray());
				
				H.Clear();
				H.TrimExcess();
				H.AddRange(HMAC_hash_H.Hash);

				data.AddRange(H.ToArray());
				msg = "Hash " + i.ToString();
				
				A0.Clear();
				A0.TrimExcess();
				A0.AddRange(A.ToArray());
				i = i + 1;
			} while (data.Count <= reqLength);
			
			if (data.Count == reqLength)
			{
				return data.ToArray();
			}
			else
			{
				return data.GetRange(0, reqLength).ToArray();
			}
		}

		public void PrintHandshakeMessages()
		{
			this.common.PrintBuf(this.cHello_hs, (String) "Client Hello:");
			this.common.PrintBuf(this.sHello_hs, (String) "Server Hello:");
			this.common.PrintBuf(this.sCert_hs, (String) "Server Certificate:");
			this.common.PrintBuf(this.pre_master_secret, (String) "Client Pre-Master Secret:");
			if (this.HasServerKeyExchange())
			{
				this.common.PrintBuf(this.sKeyExch_hs, (String) "Server Key Exchange:");
				this.common.PrintBuf(this.client_pub_key.ToByteArray(), "Client Public Key:");
			}
			this.common.PrintBuf(this.sHelloDone_hs, (String) "Server Hello Done:");
			this.common.PrintBuf(this.cke_hs, (String) "Client Key Exchange:");
			

		}

		public class TLSHandshake
		{
			byte hs_type;
			byte[] hs_length;
			byte[] hs_value;
			
			List<byte> hs_pkt = new List<byte>();
			public TLSHandshake(byte type, UInt32 lngth, byte[] vlue)
			{
				this.hs_type = type;
				byte[] lnBuf = BitConverter.GetBytes(lngth);
				this.hs_length = new byte[] {lnBuf[2], lnBuf[1], lnBuf[0]};
				this.hs_value = vlue;
			}
			
			public List<byte> CreateHS()
			{
				this.hs_pkt.Add(this.hs_type);
				this.hs_pkt.AddRange(this.hs_length);
				this.hs_pkt.AddRange(this.hs_value);
				return this.hs_pkt;
			}
		}
		public int SendHS(byte type)
		{
			try
			{
				this.hs = new TLSHandshake((byte) type, (UInt32) this.pktBuf.Count, this.pktBuf.ToArray());
				this.hsBuf = this.hs.CreateHS();

				int hsType = this.common.ReadAtLoc(this.hsBuf.ToArray(), 0, 1);
				this.hsLen = (short) this.hsBuf.Count;

				if (hsType == 1)
				{
					this.cHello_hs = new byte[this.hsLen];
					Array.Copy(this.hsBuf.ToArray(), 0, this.cHello_hs, 0, this.hsLen);
				}

				if (hsType == 16)
				{
					this.cke_hs = new byte[this.hsLen];
					Array.Copy(this.hsBuf.ToArray(), 0, this.cke_hs, 0, this.hsLen);
				}

				this.rec = new TLSRecord(0x16, (short) 0x303, this.hsLen, this.hsBuf.ToArray());

				this.recBuf = this.rec.GetBytes();
				this.recLen = (short) this.recBuf.Count;

				this.ns.Write(this.recBuf.ToArray(), 0, this.recLen);

				this.ReallocBufs();
			}
			catch (Exception e)
			{
				this.sendExcp = e;
				return -1;
			}
			return 0;
		}
		
		
		public int ParseHS()
		{
			int pktType = this.common.ReadAtLoc(this.serverResp, this.bytesProcessed, 1);
			int hsType;

			if (pktType == 22)
			{
				this.recLen = (short) this.common.ReadAtLoc(this.serverResp, this.bytesProcessed + 3, 2);
				this.hsLen = (short) this.common.ReadAtLoc(this.serverResp, this.bytesProcessed + 6, 3);
				hsType = this.common.ReadAtLoc(this.serverResp, this.bytesProcessed + 5, 1);

				try
				{
					if (hsType == 2)
					{
						if (hsLen != 0)
						{
							this.sHello_hs = new byte[this.hsLen + 4];

							Array.Copy(this.serverResp, this.bytesProcessed + 5, this.sHello_hs, 0, this.hsLen + 4);
							byte[] serv_random = new byte[32];
							Array.Copy(this.sHello_hs, 6, serv_random, 0, 32);

							this.server_random_list = new List<byte>();
							this.server_random_list.AddRange(serv_random);
						}
					}
					else if (hsType == 11)
					{
						if (hsLen != 0)
						{
							this.sCert_hs = new byte[this.hsLen + 4];
							Array.Copy(this.serverResp, this.bytesProcessed + 5, this.sCert_hs, 0, this.hsLen + 4);
						}
					}
					else if (hsType == 14)
					{
						this.sHelloDone_hs = new byte[4];
						Array.Copy(this.serverResp, this.bytesProcessed + 5, this.sHelloDone_hs, 0, 4);
					}
					else if (hsType == 12)
					{
						if (hsLen != 0)
						{
							this.sKeyExch_hs = new byte[this.hsLen + 4];
							Array.Copy(this.serverResp, this.bytesProcessed + 5, this.sKeyExch_hs, 0, this.hsLen + 4);
						}
					}			
				}
				catch (Exception exp)
				{
					Console.WriteLine(exp.ToString());
					Console.WriteLine("Exception in Response handling");
					return -2;
				}


				if ((this.hsLen + 4) == this.recLen)
				{
					this.bytesProcessed = this.bytesProcessed + this.recLen + 5;
				} else
				{
					this.bytesProcessed = this.bytesProcessed + this.hsLen + 4 + 5;
				}

				if (this.lastBytesRead > this.bytesProcessed)
				{
					return -1;
				}
				else
				{
					return 0;
				}

			}
			else 
			{
				this.hsLen = (short) this.common.ReadAtLoc(this.serverResp, this.bytesProcessed + 1, 3);
				hsType = this.common.ReadAtLoc(this.serverResp, this.bytesProcessed, 1);
				
				try
				{
					if (hsType == 2)
					{
						if (hsLen != 0)
						{
							this.sHello_hs = new byte[this.hsLen + 4];

							Array.Copy(this.serverResp, this.bytesProcessed, this.sHello_hs, 0, this.hsLen + 4);
							byte[] serv_random = new byte[32];
							Array.Copy(this.sHello_hs, 6, serv_random, 0, 32);

							this.server_random_list = new List<byte>();
							this.server_random_list.AddRange(serv_random);
						}
					}
					else if (hsType == 11)
					{
						if (hsLen != 0)
						{
							this.sCert_hs = new byte[this.hsLen + 4];
							Array.Copy(this.serverResp, this.bytesProcessed, this.sCert_hs, 0, this.hsLen + 4);
						}
					}
					else if (hsType == 14)
					{
						this.sHelloDone_hs = new byte[4];
						Array.Copy(this.serverResp, this.bytesProcessed, this.sHelloDone_hs, 0, 4);
					}
					else if (hsType == 12)
					{
						if (hsLen != 0)
						{
							this.sKeyExch_hs = new byte[this.hsLen + 4];
							Array.Copy(this.serverResp, this.bytesProcessed, this.sKeyExch_hs, 0, this.hsLen + 4);
						}
					}			
				}
				catch (Exception exp)
				{
					Console.WriteLine(exp.ToString());
					Console.WriteLine("Exception in Response handling");
					return -2;
				}


				this.bytesProcessed = this.bytesProcessed + this.hsLen + 4;

				
				if (this.lastBytesRead > this.bytesProcessed)
				{
					return -1;
				}
				else
				{
					return 0;
				}
				
			}
			this.ReallocTemp();
		}

		public int RecvHS()
		{
			byte[] buf = new byte[8192];
			int curBytes = -1;
			
			this.ns.ReadTimeout = (int) this.timeout;
			curBytes = this.ns.Read (buf, 0, 8192);
			Array.Copy(buf, 0, this.serverResp, 0, curBytes);
			this.lastBytesRead = curBytes;
			
			while (curBytes != 0)
			{
				try
				{
					curBytes = this.ns.Read (buf, 0, 8192);
					Array.Copy(buf, 0, this.serverResp, this.lastBytesRead, curBytes);
					this.lastBytesRead = this.lastBytesRead + curBytes;
				} catch 
				{
					break;
				}
			}
						
			if (this.serverResp[0] != 22)
			{
				return -1;
			}
			return 0;
		}

		public int RecvRec()
		{
			byte[] buf = new byte[8192];
			int curBytes = -1;
			
			this.ns.ReadTimeout = (int) this.timeout;
			
			try
			{
				curBytes = this.ns.Read (buf, 0, 8192);
			}
			catch (Exception exp)
			{
				return -1;
			}
			Array.Copy(buf, 0, this.serverResp, 0, curBytes);
			this.lastBytesRead = curBytes;
			
			while (curBytes != 0)
			{
				try
				{
					curBytes = this.ns.Read (buf, 0, 8192);
					Array.Copy(buf, 0, this.serverResp, this.lastBytesRead, curBytes);
					this.lastBytesRead = this.lastBytesRead + curBytes;
				} catch 
				{
					break;
				}
			}

			if (this.serverResp[0] != 23)
			{
				return -1;
			}
			return 0;
		}
		
		public void ParseServerHandshakeMessages()
		{
			int result;
			do
			{
				result = this.ParseHS();
				if (result == -2)
				{
					break;
				}
			}while (result !=0);

			this.errorCode = result;
		}
		
		public void StoreClientHelloParams(List<byte> random)
		{
			this.client_random_list = random;
			this.client_random = this.client_random_list.ToArray();
		}
		public void StoreCKEParams(List<byte> cke_hs, List<byte> pmKey, ECDiffieHellmanCng e, ECDiffieHellmanPublicKey s, ECDiffieHellmanPublicKey c)
		{
			this.cke_hs = cke_hs.ToArray();
			this.pre_master_secret = pmKey.ToArray();
			this.ecdhc = e;
			this.server_pub_key = s;
			this.client_pub_key = c;
		}
		
		public void SendHandshakeMessage(List<byte> data, byte msgType)
		{
			this.pktBuf = data;
			int result = this.SendHS(msgType);
			String msgTypeStr = this.GetMessageType(msgType);
			this.common.HandleResult(result, "Sending Handshake Message - " + msgTypeStr);
			this.errorCode = result;
		}
		
		public void ReceiveHandshakeMessage()
		{
			int result = this.RecvHS();
			this.common.HandleResult(result, "Receiving Handshake Message(s)");
			this.errorCode = result;
		}
		
		public void SendClientFinished()
		{
			TLSHandshake h = new LibTLSClient.TLSHandshake((byte) 0x14, (UInt32) this.verify_data.Length, this.verify_data);

			this.cFinished = h.CreateHS().ToArray();

			ENCTLSRecord enc;
			enc = new LibTLSClient.ENCTLSRecord(this.cFinished, 0, 3, 3, this);
			byte[] encFinished = enc.GetBytes();
			this.ns.Write(encFinished, 0, encFinished.Length);

			this.ns.Flush();
			Array.Clear(encFinished, 0, encFinished.Length);
			this.common.HandleResult(0, "Sending Client Finished");
		}
		
		public void ReadServerFinished()
		{
			this.ns.Read(this.serverResp, 0, 8192);
			int msgType = this.common.ReadAtLoc(this.serverResp, 0, 1);

			if (msgType == 21)
			{
				this.common.HandleResult(1, "Receiving Handshake Message - Server Finished");
				msgType = this.common.ReadAtLoc(this.serverResp, 6, 1);

				this.errorCode = msgType;
			} else if (msgType == 22)
			{
				this.common.HandleResult(0, "Receiving Handshake Message - Server Finished");
				msgType = this.common.ReadAtLoc(this.serverResp, 6, 1);

				this.errorCode = msgType;
			}
			Array.Clear(this.serverResp, 0, this.serverResp.Length);			
		}
		
		public void SendHTTPSData(String data)
		{
			ENCTLSRecord enc1;
			enc1 = new ENCTLSRecord(Encoding.ASCII.GetBytes(data + "\r\n\r\n"), 1, 3, 3, this);
			enc1.SetHS(false);
			byte[] encHTTP = enc1.GetBytes();
			this.ns.Write(encHTTP, 0, encHTTP.Length);
			this.ns.Flush();
			Array.Clear(encHTTP, 0, encHTTP.Length);
		}
		
		public void ReadHTTPSData()
		{
			int response = this.RecvRec();
						
			if (response == -1)
			{
				this.common.HandleResult(0, "Receiving Application Record");
				this.errorCode = 1;
			}

			int msgT = this.common.ReadAtLoc(this.serverResp, 0, 1);

			this.errorCode = msgT;
		}

		public void ParseHTTPSData()
		{
			int msgSize = this.common.ReadAtLoc(this.serverResp, 3, 2);

			this.serverEncResp = new byte[msgSize];
			try
			{
				Array.Copy(this.serverResp, 5, this.serverEncResp, 0, msgSize);

			}
			catch 
			{

			}
		}

		public String ErrorCodeToString(int code)
		{
			if (code == 21)
			{
				return (String) "Alert: Decrypt Failed";
			} else if (code == 20)
			{
				return (String) "Alert: Bad Record MAC";
			} else if (code == 0)
			{
				return (String) "Handshake Successful";
			} else if (code == 23)
			{
				return (String) "Record Successful";
			} else
			{
				return (String) "Unknown Error";
			}

		}
		
		public String GetMessageType(byte msgId)
		{
			if (msgId == 0x1)
			{
				return (String) "Client Hello";
			} else if (msgId == 0x10)
			{
				return (String) "Client Key Exchange";
			} else
			{
				return (String) "Unknown";
			}
		}
		public void SendChangeCipherSpec()
		{
			this.css_hs = new byte[1];
			this.css_hs[0] = 0x1;

			TLSRecord css = new TLSRecord(0x14, (short) 0x303, 1, this.css_hs);
			List <byte> cssBuf = css.GetBytes();
			this.ns.Write(cssBuf.ToArray(), 0, cssBuf.Count); 
		}
		public bool HasServerKeyExchange()
		{
			if (this.sKeyExch_hs != null)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public void ReallocBufs()
		{
			this.hsBuf.TrimExcess();
			this.recBuf.TrimExcess();
			this.pktBuf.TrimExcess();
			
			this.hsBuf = new List<byte>();			
			this.recBuf = new List<byte>();			
			this.pktBuf = new List<byte>();	
			
		}
		
		public void InitBufs()
		{
			this.hsBuf = new List<byte>();			
			this.recBuf = new List<byte>();			
			this.pktBuf = new List<byte>();	
			this.temp2 = new byte[2];
			this.temp3 = new byte[3];
			this.temp4 = new byte[4];
			this.serverResp = new byte[163840];

		}
		public void CreateTCPConn(String server, Int32 port)
		{
			try
			{
				this.client = new TcpClient();
				var connResult = this.client.BeginConnect(server, port, null, null);
				var success = connResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(10));
				this.ns = this.client.GetStream();
			} catch (Exception tcpE)
			{
				this.errorCode = 1;
				return;
			}
		}
		
		public void ReallocTemp()
		{
			Array.Clear(this.temp2, 0, this.temp2.Length);
			Array.Clear(this.temp3, 0, this.temp3.Length);
			Array.Clear(this.temp4, 0, this.temp4.Length);
			this.temp2 = new byte[2];
			this.temp3 = new byte[3];
			this.temp4 = new byte[4];
		}
		public int GetInt(byte[] bArray, int spos)
		{
			Array.Reverse(bArray);
			return BitConverter.ToInt32(bArray, spos);
		}
		
		public short GetShort(byte[] bArray, int spos)
		{
			Array.Reverse(bArray);
			return BitConverter.ToInt16(bArray, spos);
		}
		
		public int GetThreeBytes(byte[] bArray, int spos)
		{
			Array.Reverse(bArray);
			int result = 0;
			result = result + (bArray[0] & 0xf);
			result = result + (((bArray[0] & 0xf0) >> 4) * 0x10);
			if (spos == 2)
			{
				return result;
			}

			result = result + ((bArray[1] & 0xf) * 0x100);
			result = result + (((bArray[1] & 0xf0) >> 4) * 0x1000);
			if (spos == 1)
			{
				return result;
			}
	
			result = result + ((bArray[2] & 0xf) * 0x10000);
			result = result + (((bArray[2] & 0xf0) >> 4) * 0x100000);
			
			return result;
		}
	}
}


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
using handshake;
using crypto;
using SecureClient;
using common;
using System.Numerics;

namespace sslC
{
	class sslC
	{
		void TcpExceptionMsg()
		{
			Console.WriteLine("Exception in TCP communication, quitting");
			Console.WriteLine("Exception:");
		}
	
		[STAThread]
		static void Main()
		{
			
			LibTLSClient cSSL;
			Common cf;
			Encryption e;
			Cipher c;
			ClientHello clientHello;
			ClientKeyExchange cke;

			int debug = 0;
			String request = "";
			string[] args = Environment.GetCommandLineArgs();
			
			try
			{
				debug = (int) UInt32.Parse(args[4]);
				
				if (debug == 1)
				{
					Console.WriteLine("Server: {0} Port: {1} Cipher: {2} Debug: {3}", args[1], args[2], args[3], args[4]);
				}
				request = args[5];
				cf = new Common(debug);
				
				e = new Encryption();
				cSSL = new LibTLSClient(cf, e);
				
				cSSL.cipher = UInt32.Parse(args[3], System.Globalization.NumberStyles.HexNumber);
				c = new Cipher((ushort) cSSL.cipher);
				cSSL.cipherObj = c;
				cSSL.serverIP = args[1];
			}
			catch (Exception ex)
			{
				Console.WriteLine("<prog> <ip/fqdn> <port> <cipher hex> <debug [0/1/2]> <a GET request>");
				Console.WriteLine("Example: TLSClient.exe 10.209.113.104 443 002f 2 \"GET / HTTP/1.1\"");
				return;
			}

			if (c.Supported() == false)
			{
				Console.WriteLine("Cipher Suite not supported currently");
				Console.WriteLine("Please try 002f/0035/003c/003d/009c/009d");
				return;
			}

			cSSL.CreateTCPConn(args[1], Convert.ToInt32(args[2]));
			cf.HandleResult(cSSL.errorCode, "TCP Connection");
			cf.ExitOnError(cSSL.errorCode);
	
			cSSL.InitBufs();

			List <UInt32> cipher_suites = new List<UInt32>();
			cipher_suites.Add(cSSL.cipher);

			String clientIP = cSSL.GetIPAddress();
			String serverIP = cSSL.serverIP;

			clientHello = new ClientHello(clientIP, serverIP, 3, 3, false, cipher_suites);
			
			List<byte> chello_hs = clientHello.Get();
			
			List<byte> crandom = clientHello.GetRandom();
			
			cSSL.StoreClientHelloParams(crandom);
			
			cSSL.SendHandshakeMessage(chello_hs, 0x1);
			cf.ExitOnError(cSSL.errorCode);
			
			cSSL.ReceiveHandshakeMessage();
			cf.ExitOnError(cSSL.errorCode);
			
			cSSL.ParseServerHandshakeMessages();
			cf.ExitOnError(cSSL.errorCode);

			if (cSSL.HasServerKeyExchange())
			{
				cke = new ClientKeyExchange(cf, cSSL.sCert_hs, 3, 3, cSSL.sKeyExch_hs, (String) "ECDHE");
			}
			else
			{
				cke = new ClientKeyExchange(cf, cSSL.sCert_hs, 3, 3, null, (String) "RSA");
			}

			List<byte> cke_hs = cke.CreateCKE();
			
			cSSL.StoreCKEParams(cke_hs, cke.GetPremasterSecret(), cke.ecdhCngClient, cke.server_pub_key, cke.client_pub_key);
			
			cSSL.SendHandshakeMessage(cke_hs, 0x10);
			cf.ExitOnError(cSSL.errorCode);

			cSSL.PrintHandshakeMessages();
			
			cSSL.SendChangeCipherSpec();
			
			cSSL.ComputeMasterSecret();
			cSSL.ComputeVerifyData();
			cSSL.ComputeKeys();

			cSSL.SendClientFinished();
			cSSL.ReadServerFinished();
			cf.debugPrint(cSSL.ErrorCodeToString(cSSL.errorCode));

			if (cSSL.errorCode != 0)
			{
				return;
			}
			cSSL.SendHTTPSData(request);

			cSSL.ReadHTTPSData();			
			cf.debugPrint(cSSL.ErrorCodeToString(cSSL.errorCode));
			cSSL.ParseHTTPSData();
			
			byte[] dec = cSSL.DecryptResp();
			
			String dec_s = Encoding.ASCII.GetString(dec, 0, dec.Length);

			if ((dec_s.IndexOf("HTTP") == 0) && (debug == 0))
			{
				Console.WriteLine("{0} Successful", cSSL.cipherObj.cipher_name);
			}
			
			if ((debug == 2) || (debug == 1))
			{
				Console.WriteLine(dec_s);
			}
		
		}
	}
}

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

namespace common
{
	public class Common
	{
		public byte[] temp;
		public byte[] temp2;
		public byte[] temp3;
		public byte[] temp4;
		int debug;
		public int pythonFormat = 0;
		
		public Common(int dbg)
		{
			this.debug = dbg;
		}
		
		public int ReadAtLoc(byte[] data, int loc, int numBytes)
		{
			this.temp = new byte[1];
			this.temp2 = new byte[2];
			this.temp3 = new byte[3];
			this.temp4 = new byte[4];
			
			if (numBytes == 1)
			{
				return data[loc];
			}
			else if (numBytes == 2)
			{
				Array.Copy(data, loc, this.temp2, 0, numBytes);
				return this.GetShort(this.temp2, 0);
			}
			else if (numBytes == 3)
			{
				Array.Copy(data, loc, this.temp3, 0, numBytes);
				return this.GetThreeBytes(this.temp3, 0);
			}
			return -1;
		}
		
		public void ExitOnError(int result)
		{
			if (result != 0)
			{
				System.Environment.Exit(result);
			}
		}

		public void HandleResult(int result, String customMsg)
		{
			if (this.debug == 1)
			{
				if (result == 0)
				{
					Console.WriteLine(customMsg + " Succeeded");
				} else
				{
					Console.WriteLine(customMsg + " Failed");
					
				}
			}
		}

		public void PrintBuf(byte[] data, String heading)
		{
			int numBytes = 0;

			if (this.debug == 1)
			{
				if (data == null)
				{
					return;
				}

				if (this.pythonFormat == 1)
				{
					Console.Write(heading + "\"");

					foreach (byte element in data)
					{
						Console.Write("\\x{0}", element.ToString("X2"));
						numBytes = numBytes + 1;
					}
					Console.Write("\"\r\n");

				}
				else
				{
					Console.WriteLine(heading);

					foreach (byte element in data)
					{
						Console.Write("{0, 4}", element.ToString("X2"));
						numBytes = numBytes + 1;
						if (numBytes == 32)
						{
							Console.Write("\r\n");
							numBytes = 0;
						}
					}
					Console.Write("\r\n");
				}
			}
			
		}

		public void debugPrint(String msg, params object[] args)
		{
			if (this.debug == 1)
			{
				Console.WriteLine(msg, args);
			}
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
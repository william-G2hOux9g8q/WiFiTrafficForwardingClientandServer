using System;

namespace CSBeaconSpamClient
{
    class Program
    {
        void WriteFrame(byte[] b)
        {
            System.Text.StringBuilder debugOut = new System.Text.StringBuilder();
            debugOut.Append("Sent frame (");
            debugOut.Append(b.Length);
            debugOut.Append("): ");
            foreach (var bb in b)
                debugOut.Append(bb.ToString("X2"));
            Utility.DebugWriteLine(debugOut.ToString());
        }

        static async System.Threading.Tasks.Task Main(string[] args)
        {
            if (args.Length != 2)
            {
                Utility.WriteLine("Usage: {0} <server address> <server listen port>", "dotnet run");
                return;
            }
            if (!System.Net.IPAddress.TryParse(args[0], out var serverAddress))
            {
                Utility.WriteLine("Could not convert argument to IP address: {0}", args[0]);
                return;
            }
            if (!int.TryParse(args[1], out var serverPort) || serverPort < 1 || serverPort > 65535)
            {
                Utility.WriteLine("Could not convert argument to network port: {0}", args[1]);
                return;
            }
            Utility.WriteLine("Connecting to server");
            System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient();
            try
            {
                client.Connect(serverAddress, serverPort);
            }
            catch (Exception ex)
            {
                Utility.WriteLine("Error connecting to server: " + ex.ToString());
                return;
            }
            Utility.WriteLine("Generating beacons and sending to server");
            var stream = client.GetStream();
            var toSend = new byte[5000];
            try
            {
                var crc = new Crc32();
                for (; client.Connected;)
                {
                    //System.Threading.Thread.Sleep(500);
                    byte[] b = new byte[Utility.TestBeacon.Length];
                    using (var msC = new System.IO.MemoryStream())
                    {
                        using (var zstd = new Zstandard.Net.ZstandardStream(msC, System.IO.Compression.CompressionMode.Compress))
                        {
                            zstd.CompressionLevel = 1;
                            Array.Copy(Utility.TestBeacon, b, b.Length);
                            byte[] mac = new byte[3];
                            Utility.RandomNumberGenerator.GetBytes(mac);
                            Array.Copy(mac, 0, b, 49, 3);
                            Array.Copy(mac, 0, b, 54, 3);
                            string s1 = mac[0].ToString("X2");
                            string s2 = mac[1].ToString("X2");
                            string s3 = mac[2].ToString("X2");
                            var s1b = System.Text.ASCIIEncoding.ASCII.GetBytes(s1);
                            var s2b = System.Text.ASCIIEncoding.ASCII.GetBytes(s2);
                            var s3b = System.Text.ASCIIEncoding.ASCII.GetBytes(s3);
                            b[85] = s1b[0];
                            b[86] = s1b[1];
                            b[87] = s2b[0];
                            b[88] = s2b[1];
                            b[89] = s3b[0];
                            b[90] = s3b[1];

                            byte[] getCRC = new byte[b.Length - 40];
                            Array.Copy(b, 36, getCRC, 0, getCRC.Length);
                            var crc32Calc = crc.Get<byte>(getCRC);
                            b[b.Length - 4] = (byte)(crc32Calc & 0xFF);
                            b[b.Length - 3] = (byte)((crc32Calc & 0xFF00) >> 8);
                            b[b.Length - 2] = (byte)((crc32Calc & 0xFF0000) >> 16);
                            b[b.Length - 1] = (byte)((crc32Calc & 0xFF000000) >> 24);

                            zstd.Write(b, 0, b.Length);
                            zstd.Close();
                            toSend = msC.ToArray();
                        }
                    }
                    byte[] lenBuffer = BitConverter.GetBytes(toSend.Length);

                    await stream.WriteAsync(lenBuffer);
                    await stream.WriteAsync(toSend);
                }
            }
            catch (Exception ex)
            {
                Utility.WriteLine("Got exception sending beacon: " + ex.ToString());
                return;
            }
        }
    }
}

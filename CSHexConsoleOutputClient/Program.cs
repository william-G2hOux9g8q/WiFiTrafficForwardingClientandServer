using System;

namespace CSHexConsoleOutputClient
{
    class Program
    {
        public const bool RawOutput = true;
        public const int PacketBufferSize = 9500 + 2000;

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
            if (!RawOutput)
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
            if (!RawOutput)
                Utility.WriteLine("Reading from server and dumping traffic to console");
            var stream = client.GetStream();
            byte[] lenBuffer = new byte[4];
            int length;
            byte[] frameBuffer = new byte[PacketBufferSize];
            int offset;
            byte[] dec;
            try
            {
                for (; client.Connected;)
                {
                    offset = 0;
                    while (offset < 4)
                    {
                        offset = await stream.ReadAsync(lenBuffer, offset, 4 - offset);
                        if (offset < 1)
                        {
                            throw new System.IO.EndOfStreamException("Short read of length buffer");
                        }
                    }
                    length = BitConverter.ToInt32(lenBuffer, 0);
                    if (!RawOutput)
                        Utility.DebugWriteLine("Got frame length: " + length);
                    offset = 0;
                    while (offset < length)
                    {
                        offset = await stream.ReadAsync(frameBuffer, offset, length - offset);
                        if (offset < 1)
                        {
                            throw new System.IO.EndOfStreamException("Short read of frame buffer");
                        }
                    }
                    using (var msC = new System.IO.MemoryStream(frameBuffer, 0, length))
                    {
                        using (var zstd = new Zstandard.Net.ZstandardStream(msC, System.IO.Compression.CompressionMode.Decompress))
                        {
                            using (var msD = new System.IO.MemoryStream())
                            {
                                zstd.CopyTo(msD);
                                dec = msD.ToArray();
                            }
                        }
                    }
                    if (!RawOutput)
                    {
                        System.Text.StringBuilder debugOut = new System.Text.StringBuilder();
                        debugOut.Append("Decompressed frame (");
                        debugOut.Append(dec.Length);
                        debugOut.Append("): ");
                        foreach (var b in dec)
                            debugOut.Append(b.ToString("X2"));
                        Utility.DebugWriteLine(debugOut.ToString());
                    }
                    else
                    {
                        System.Text.StringBuilder debugOut = new System.Text.StringBuilder();
                        foreach (var b in dec)
                            debugOut.Append(b.ToString("X2"));
                        Utility.DebugWriteLine(debugOut.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Utility.WriteLine("Got exception reading data: " + ex.ToString());
                return;
            }
        }
    }
}
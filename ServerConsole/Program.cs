#define DEBUG_OUTPUT

using System;

namespace ServerConsole
{
    class Program
    {
        public const int MaxSendBufferQueue = 100;
        //technically should be the value in the client program + possible overhead for ZSTD header...
        public const int PacketBufferSize = 9500 + 2000;
        class Client
        {
            public System.Net.Sockets.TcpClient Socket;
            public System.Net.Sockets.NetworkStream Stream;
            public object SendBufferLock;
            public System.Collections.Generic.Queue<byte[]> SendBufferQueue;
            public System.Threading.AutoResetEvent SendBufferARE;
            public long TotalPackets;
            public long TotalData;
            public long DroppedPackets;
            public DateTime ConnectionTime;

            public Client(System.Net.Sockets.TcpClient socket)
            {
                SendBufferLock = new object();
                SendBufferQueue = new System.Collections.Generic.Queue<byte[]>(MaxSendBufferQueue);
                SendBufferARE = new System.Threading.AutoResetEvent(false);
                Socket = socket;
                Stream = socket.GetStream();
                ConnectionTime = DateTime.Now;
            }
        }
        static System.Collections.Generic.List<Client> Clients = new System.Collections.Generic.List<Client>();
        static object ClientsLock = new object();

        private static void FillClientBuffers(Client sender, byte[] sourceBuffer, int sourceBufferLength)
        {
            byte[] buffer = new byte[sourceBufferLength];
            Array.Copy(sourceBuffer, buffer, sourceBufferLength);
            var toRemove = new System.Collections.Generic.List<Client>();
            lock (ClientsLock)
            {
                for (int i = 0; i < Clients.Count; ++i)
                {
                    if (!Clients[i].Socket.Connected)
                        toRemove.Add(Clients[i]);
                    else if (Clients[i] != sender)
                    {
                        lock (Clients[i].SendBufferLock)
                        {
                            if (Clients[i].SendBufferQueue.Count < MaxSendBufferQueue)
                                Clients[i].SendBufferQueue.Enqueue(buffer);
                            else
                                ++Clients[i].DroppedPackets;
                            Clients[i].SendBufferARE.Set();
                        }
                    }
                }
                //also need to set ARE?
                foreach (var client in toRemove)
                    Clients.Remove(client);
            }
            toRemove.Clear();
        }
        //need some kind of buffer or something that stores packets to send to client
        //can't just send to all since disconnect/slow client will slow down all other clients
        //TODO: Display: maybe clear and for each client keep in dictionary, keep stats (packets, total length, compress length, ratio, etc.)
        static System.Collections.Concurrent.ConcurrentQueue<string> ClientQ = new System.Collections.Concurrent.ConcurrentQueue<string>();
        async static System.Threading.Tasks.Task RecvFromClient(Client client)
        {
            var stream = client.Stream;
            byte[] lenBuffer = new byte[4];
            int length;
            byte[] frameBuffer = new byte[PacketBufferSize];
            int offset, readLength;
            try
            {
                for (; ; )
                {
                    //Utility.DebugWriteLine("Waiting for frame length");
                    ClientQ.Enqueue("Waiting for frame length");
                    offset = 0;
                    while (offset < 4)
                    {
                        //Utility.DebugWriteLine("Reading data: {0}, {1}", offset, 4 - offset);
                        ClientQ.Enqueue(string.Format("Reading length: {0}, {1}", offset, 4 - offset));
                        readLength = await stream.ReadAsync(lenBuffer, offset, 4 - offset);
                        if (readLength < 1)
                        {
                            throw new System.IO.EndOfStreamException("Short read of length buffer");
                        }
                        offset += readLength;
                    }
                    length = BitConverter.ToInt32(lenBuffer, 0);
                    //Utility.DebugWriteLine("Got frame length: " + length);
                    ClientQ.Enqueue("Got frame length: " + length);
                    offset = 0;
                    while (offset < length)
                    {
                        //Utility.DebugWriteLine("Reading data: {0}, {1}", offset, length - offset);
                        ClientQ.Enqueue(string.Format("Reading data: {0}, {1}", offset, length - offset));
                        readLength = await stream.ReadAsync(frameBuffer, offset, length - offset);
                        if (readLength < 1)
                        {
                            throw new System.IO.EndOfStreamException("Short read of frame buffer");
                        }
                        offset += readLength;
                    }
                    client.TotalPackets += 1;
                    client.TotalData += length;
                    FillClientBuffers(client, frameBuffer, length);
                    while (ClientQ.Count > 50)
                        ClientQ.TryDequeue(out string discard);
                }
            }
            catch (Exception ex)
            {
                Utility.WriteLine("Got exception in RecvFromClient: " + ex.ToString());
                ClientQ.Enqueue(string.Format("Got exception in RecvFromClient: " + ex.ToString()));
            }
            try
            {
                client.Socket.Dispose();
            }
            catch { }
            Utility.WriteLine("Leaving RecvFromClient");
            ClientQ.Enqueue("Leaving RecvFromClient");
        }
        async static System.Threading.Tasks.Task SendToClient(Client client)
        {
            byte[] toSend;
            byte[] toSendLength;
            for (; client.Socket.Connected;)
            {
                client.SendBufferARE.WaitOne();
                lock (client.SendBufferLock)
                {
                    if (client.SendBufferQueue.Count == 1)
                        toSend = client.SendBufferQueue.Dequeue();
                    else if (client.SendBufferQueue.Count > 1)
                    {
                        toSend = client.SendBufferQueue.Dequeue();
                        client.SendBufferARE.Set();
                    }
                    else
                    {
                        Utility.WriteLine("Got empty queue in SendToClient");
                        continue;
                    }
                }
                if (client.SendBufferQueue.Count > 0)
                    client.SendBufferARE.Set();
                toSendLength = BitConverter.GetBytes(toSend.Length);
                await client.Stream.WriteAsync(toSendLength, 0, toSendLength.Length);
                await client.Stream.WriteAsync(toSend, 0, toSend.Length);
            }
            return;
        }
        async static void ProcessTCPClient(object arg)
        {
            var client = (System.Net.Sockets.TcpClient)arg;
            string ep = client.Client.RemoteEndPoint.ToString();
            //TODO: add buffer for decompressed and log statistics (compress ratio)
            using (client)
            {
                try
                {
                    var clientData = new Client(client);
                    lock (ClientsLock)
                        Clients.Add(clientData);
                    var readTask = RecvFromClient(clientData);
                    var writeTask = SendToClient(clientData);
                    await System.Threading.Tasks.Task.WhenAll(readTask, writeTask);
                }
                catch (Exception ex)
                {
                    Utility.DebugWriteLine("Got exception in ProcessTCPClient ({0}): {1}", ep, ex.ToString());
                }
            }
            Utility.WriteLine("Leaving ProcessTCPClient");
        }
        static async System.Threading.Tasks.Task ListenThread(System.Net.IPAddress listenAddress, int port)
        {
            string errorMessage = null;
            System.Net.Sockets.TcpListener listen = null;
            Utility.WriteLine("Entering ListenThread");
            try
            {
                listen = new System.Net.Sockets.TcpListener(new System.Net.IPEndPoint(listenAddress, port));
                listen.Start();
            }
            catch (Exception ex)
            {
                errorMessage = "Got error listening on TCP: " + ex.ToString();
            }
            for (; errorMessage == null;)
            {
                try
                {
                    var c = await listen.AcceptTcpClientAsync();
                    Utility.DebugWriteLine("Got client connection: {0}", c.Client.RemoteEndPoint.ToString());
                    //just use threads since there aren't going to be thousands of clients...
                    var pts = new System.Threading.ParameterizedThreadStart(ProcessTCPClient);
                    var t = new System.Threading.Thread(pts);
                    t.Start(c);
                }
                catch (Exception ex)
                {
                    errorMessage = "Got exception in listen loop: " + ex.ToString();
#if DEBUG_OUTPUT
                    Utility.DebugWriteLine(errorMessage);
                    errorMessage = null;
                    System.Threading.Thread.Sleep(1000);
#endif
                }
            }
            if (errorMessage != null)
                Utility.WriteLine(errorMessage);
            Utility.WriteLine("Leaving ListenThread");
            listen.Stop();
        }

        static async System.Threading.Tasks.Task StatusOutputThread()
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (; ; )
            {
                System.Threading.Thread.Sleep(1000);
                sb.Clear();
                lock (ClientsLock)
                {
                    foreach (var client in Clients)
                    {
                        if (!client.Socket.Connected)
                            continue;
                        sb.Append("Client: ");
                        sb.AppendLine(client.Socket.Client.RemoteEndPoint.ToString());
                        sb.Append("Connection duration: ");
                        TimeSpan diff = DateTime.Now.Subtract(client.ConnectionTime);
                        sb.AppendLine(diff.ToString());
                        sb.Append("Total packets: ");
                        sb.AppendLine(client.TotalPackets.ToString());
                        sb.Append("Total bytes: ");
                        sb.AppendLine(client.TotalData.ToByteString());
                        sb.Append("Total bytes per second: ");
                        sb.AppendLine((client.TotalData / diff.TotalSeconds).ToByteString() + "/s");
                        sb.Append("Dropped packets: ");
                        sb.AppendLine(client.DroppedPackets.ToString());
                        sb.Append("Queue size: ");
                        sb.AppendLine(client.SendBufferQueue.Count.ToString());
                        sb.AppendLine();
                    }
                }
                Console.Clear();
                Utility.WriteLine(sb.ToString());
            }
        }

        static async System.Threading.Tasks.Task Main(string[] args)
        {
            if (args.Length != 2)
            {
                Utility.WriteLine("Usage: {0} <listen address> <listen port>", "dotnet run");
                return;
            }
            if (!System.Net.IPAddress.TryParse(args[0], out var listenAddress))
            {
                Utility.WriteLine("Could not convert argument to IP address: {0}", args[0]);
                return;
            }
            if (!int.TryParse(args[1], out var listenPort) || listenPort < 1 || listenPort > 65535)
            {
                Utility.WriteLine("Could not convert argument to network port: {0}", args[1]);
                return;
            }
            var listenTask = System.Threading.Tasks.Task.Run(() => ListenThread(System.Net.IPAddress.Parse("0.0.0.0"), 4000));
            for (; ; )
            {
                var line = Console.ReadLine();
                var sb = new System.Text.StringBuilder();
                foreach (var client in Clients)
                {
                    string ep = null;
                    try
                    {
                        ep = client.Socket.Client.RemoteEndPoint.ToString();
                    }
                    catch { continue; }
                    sb.Append("Client: ");
                    sb.AppendLine(ep);
                    sb.Append("Connection duration: ");
                    TimeSpan diff = DateTime.Now.Subtract(client.ConnectionTime);
                    sb.AppendLine(diff.ToString());
                    sb.Append("Total packets: ");
                    sb.AppendLine(client.TotalPackets.ToString());
                    sb.Append("Total bytes: ");
                    sb.AppendLine(client.TotalData.ToByteString());
                    sb.Append("Total bytes per second: ");
                    sb.AppendLine((client.TotalData / diff.TotalSeconds).ToByteString() + "/s");
                    sb.Append("Dropped packets: ");
                    sb.AppendLine(client.DroppedPackets.ToString());
                    sb.Append("Queue size: ");
                    sb.AppendLine(client.SendBufferQueue.Count.ToString());
                    sb.Append("Client connected: ");
                    sb.AppendLine(client.Socket.Connected.ToString());
                    sb.AppendLine();
                }
                Utility.WriteLine(sb.ToString().Trim() + "\n");
                if (line == "debug")
                    while (ClientQ.TryDequeue(out string toPrint))
                        Utility.WriteLine(toPrint);
            }
            await listenTask;
        }
    }
}

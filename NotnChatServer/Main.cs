using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NotnChat;

struct Client
{
    public SslStream Stream;
    public string Name;
}

class Program
{
    static readonly Dictionary<TcpClient, Client> connected = new();
    static X509Certificate? certificate;
    static readonly char[] specials = new char[] { '$' };

    const int STD_OUTPUT_HANDLE = -11;
    const int NAME_LENGTH = 32;
    const int MESSAGE_LENGTH = 2000;
    const ushort MIN_PORT = 30000;
    const ushort MAX_PORT = 30009;
    const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4;
    const string GREY_TEXT = "\x1B[38;5;7m";
    const string GREEN_TEXT = "\x1B[38;5;2m";
    const string BLUE_TEXT = "\x1B[38;5;75m";

    static void SendtoAllAndServer(string input, TcpClient? except = null)
    {
        Console.WriteLine(input);
        SendToAll(input, except);
    }
    static void SendToAll(string input, TcpClient? except = null)
    {
        foreach (TcpClient client in connected.Keys)
        {
            if (client == except)
                continue;
            Send(input, client);
        }
    }
    static void Send(string input, TcpClient client, SslStream? backupStream = null)
    {
        byte[] buffer = Encoding.UTF8.GetBytes(input);
        if (backupStream == null)
            connected[client].Stream.Write(buffer, 0, buffer.Length);
        else
            backupStream.Write(buffer, 0, buffer.Length);
    }
    static void Kick(string input, TcpClient client, SslStream? backupStream = null)
    {
        Send($"${input}", client, backupStream);
        client.Close();
        if (connected.ContainsKey(client))
            connected.Remove(client);
    }

    static void NewClient(object? data)
    {
        if (data == null)
            return;

        bool retrievedName = false;
        TcpClient client = (TcpClient)data;
        NetworkStream stream = client.GetStream();
        SslStream sslStream = new(stream, false);
        IPEndPoint? endPoint = (IPEndPoint?)client.Client.RemoteEndPoint;
        if (endPoint == null)
        {
            Kick("Failed to reach end point.", client);
            return;
        }
        string IP = endPoint.Address.ToString();
        Console.WriteLine($"Incoming connection from {IP}.");

        try
        {
            if (certificate == null)
                return;
            sslStream.AuthenticateAsServer(certificate, false, true);
        }
        catch (AuthenticationException exception)
        {
            Console.WriteLine($"Rejected connection from {IP} due to not being able to verify SSL authentication:\n{exception.Message}");
            client.Close();
            return;
        }

        while (true)
        {
            try
            {
                byte[] buffer = new byte[MESSAGE_LENGTH];
                sslStream.Read(buffer, 0, buffer.Length);
                string message = Encoding.UTF8.GetString(buffer).Trim('\0');
                if (retrievedName) // User is sending a message.
                    SendtoAllAndServer($"{GREEN_TEXT}{connected[client].Name}{GREY_TEXT}: {message}", client);
                else if (buffer[0] != 0) // User has just joined the chatroom.
                {
                    foreach (KeyValuePair<TcpClient, Client> name in connected)
                    {
                        if (name.Value.Name == message)
                        {
                            Kick("This username is already being used in the chatroom.", client, sslStream);
                            Console.WriteLine($"{IP} is trying to use the username {message}, however this username is already registered. Aborting connection...");
                            return;
                        }
                    }
                    if (message.Length > 0 && specials.Contains(message[0]))
                    {
                        Kick("Cannot use special characters ($) at the start at your name.", client, sslStream);
                        Console.WriteLine($"{IP} is trying to use special characters ($). Aborting connection...");
                        return;
                    }
                    if (message.Length > 32)
                    {
                        Send("Your username has been truncated due to being longer than 32 characters.", client, sslStream);
                        message = message[..32];
                    }
                    if (connected.Count == 0)
                        Console.WriteLine("Waking up server.");
                    connected.Add(client, new Client { Name = message, Stream = sslStream });
                    Console.WriteLine($"{connected[client].Name} ({IP}) has entered the chatroom.");
                    SendToAll($"{BLUE_TEXT}{connected[client].Name} has entered the chatroom.{GREY_TEXT}", client);
                    retrievedName = true;
                }
            }
            catch (IOException) // User has just left the chatroom.
            {
                if (connected.ContainsKey(client))
                {
                    Console.WriteLine($"{connected[client].Name} ({IP}) has left the chatroom.");
                    SendToAll($"{BLUE_TEXT}{connected[client].Name} has left the chatroom.{GREY_TEXT}", client);
                }
                else
                    Console.WriteLine($"The connection from {IP} has abruptly ended, possibly due to not being able to validate SSH.");
                connected.Remove(client);
                if (connected.Count == 0)
                    Console.WriteLine("Server is now hibernating.");
                return;
            }
        }
    }

    static int Main()
    {
        // Enable ANSI escape sequences on Windows.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr GetStdHandle(int nStdHandle);

            [DllImport("kernel32.dll")]
            static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

            [DllImport("kernel32.dll")]
            static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

            IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
            GetConsoleMode(handle, out uint flags);
            SetConsoleMode(handle, flags | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }

        // App introduction.
        Console.Clear();
        Console.WriteLine($"{BLUE_TEXT}-------------------------------------------------\nLaunching NotnChat server.\n-------------------------------------------------");

        // Sort out certificate.
        if (File.Exists("certificate.pfx")) // Assume default with no password. Mostly for testing purposes.
        {
            try
            {
                certificate = new("certificate.pfx");
            }
            catch (CryptographicException exception)
            {
                Console.Write($"{GREY_TEXT}Failed to authenticate default certificate (certificate.pfx): {exception.Message}");
                certificate = null;
            }
        }
        while (certificate == null)
        {
            Console.Write($"{GREY_TEXT}Please select the path to your SSL certificate. This is required for establishing SSL security.\n>>> ");
            string? certLocation = Console.ReadLine();
            Console.Write("Please provide the password to your certificate (leave blank if it doesn't require one):\n>>> ");
            string? password = Console.ReadLine();
            if (File.Exists(certLocation))
            {
                certificate = new(certLocation, password);
                Console.Clear();
                Console.Write(BLUE_TEXT);
                break;
            }
        }

        // Get network IP.
        string ip;
        using (Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, 0))
        {
            socket.Connect("8.8.8.8", 65535);
            IPEndPoint? endPoint = (IPEndPoint?)socket.LocalEndPoint;
            if (endPoint != null)
                ip = endPoint.Address.ToString();
            else
            {
                Console.WriteLine("Could not connect to the internet.");
                return 1;
            }
        }

        // Launch listener and start accepting clients.
        for (ushort port = MIN_PORT; port <= MAX_PORT; port++)
        {
            try
            {
                Console.WriteLine($"Initiating server at address {ip}:{port}.");
                TcpListener server = new(IPAddress.Parse(ip), port);
                server.Start();
                Console.WriteLine($"Now accepting clients.{GREY_TEXT}");
                while (true)
                {
                    TcpClient client = server.AcceptTcpClient();
                    Thread thread = new(NewClient);
                    thread.Start(client);
                }
            }
            catch
            {
                Console.WriteLine($"Cannot host server at address {ip}:{port}.");
            }
        }
        Console.WriteLine($"Cannot use ports inside allocated range {MIN_PORT} - {MAX_PORT}.");
        return 1;
    }
}
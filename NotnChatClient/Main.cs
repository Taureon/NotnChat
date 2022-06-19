using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace NotnChat;

class Program
{
    static int initialHeight = 0;
    static SslStream? sslStream = null;
    static bool ping;
    static readonly StringBuilder inputStream = new();

    const int STD_OUTPUT_HANDLE = -11;
    const int NAME_LENGTH = 32;
    const int MESSAGE_LENGTH = 2000;
    const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4;
    const string GREY_TEXT = "\x1B[38;5;7m";

    // Allow for clean certificates and self-signed certificates with an untrusted root.
    static bool VerifyCertificate(object? sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
            return true;

        if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
        {
            if (chain != null && chain.ChainStatus != null)
            {
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (certificate != null && certificate.Subject == certificate.Issuer && status.Status == X509ChainStatusFlags.UntrustedRoot)
                        continue;
                    else if (status.Status != X509ChainStatusFlags.NoError)
                        return false;
                }
            }
            return true;
        }

        return false;
    }

    static void ClearCurrentLine()
    {
        int currentLine = Console.CursorTop;
        Console.SetCursorPosition(0, currentLine);
        Console.Write(new string(' ', Console.BufferWidth));
        Console.SetCursorPosition(Console.WindowWidth - 1, currentLine == 0 ? 0 : currentLine - 1);
    }

    static void Backspace(int count = 1)
    {
        for (int i = 0; i < count; ++i)
        {
            if (Console.CursorLeft == 0)
            {
                Console.SetCursorPosition(Console.WindowWidth - 1, Console.CursorTop - 1);
                Console.Write(" \b");
                Console.CursorLeft = Console.WindowWidth - 1;
            }
            else
                Console.Write("\b \b");
        }
    }

    static void SendToServer(string? input)
    {
        if (input == null || sslStream == null)            
            return;
        byte[] buffer = Encoding.UTF8.GetBytes(input);
        sslStream.Write(buffer, 0, buffer.Length);
    }

    static void Finish()
    {
        Console.WriteLine("The server has been closed abruptly.");
        Environment.Exit(0);
    }

    static string ReadLineAdjusted()
    {
        inputStream.Clear();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return inputStream.ToString();
            }
            else if (key.Key == ConsoleKey.Backspace)
            {
                if (inputStream.Length > 0)
                {
                    inputStream.Remove(inputStream.Length - 1, 1);
                    Backspace();
                }
            }
            else
            {
                inputStream.Append(key.KeyChar);
                Console.Write(key.KeyChar);
                if (Console.CursorLeft == Console.WindowWidth - 1 && inputStream.Length % Console.WindowWidth == 0)
                    Console.SetCursorPosition(0, Console.CursorTop + 1);
            }
        }
    }

    static void WriteLineAdjusted(string? input)
    {
        if (input == null)
            return;

        // Clear current input stream.
        Backspace(inputStream.Length);

        // Write text and write input stream again.
        Console.CursorLeft = 0;
        Console.WriteLine(input);
        Console.Write(inputStream);
    }

    static void ReadIncoming(object? data)
    {
        if (data == null || sslStream == null)
            return;
        TcpClient client = (TcpClient)data;
        while (true)
        {
            try
            {
                byte[] buffer = new byte[NAME_LENGTH + MESSAGE_LENGTH];
                sslStream.Read(buffer, 0, buffer.Length);
                string message = Encoding.UTF8.GetString(buffer).Trim('\0');
                if (message.Length > 0 && message[0] == '$')
                {
                    Console.WriteLine($"Your connection has been closed: {message[1..]}");
                    Environment.Exit(0);
                    break;
                }
                else if (buffer[0] == 0)
                {
                    Finish();
                    return;
                }

                // THIS CODE IS JANKY AND DOES NOT WORK OUTSIDE WINDOWS
                WriteLineAdjusted(message);
                if (ping)
                {
                    Thread thread = new(() => Console.Beep());
                    thread.Start();
                }
            }
            catch (IOException)
            {
                Finish();
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

        // Configuration.
        Console.Clear();
        Console.Write($"{GREY_TEXT}Choose your name:\n>>> ");
        string? name = Console.ReadLine();
        Console.Write("Choose the IP to connect to:\n>>> ");
        string? ip = Console.ReadLine();
        Console.Write("Allow pings? (Y/N)\n>>> ");
        string? pingText = Console.ReadLine();
        if (pingText != null)
            ping = pingText.Trim().ToLower() == "y";
        if (name == null || ip == null)
            return 1;

        // Parse the IP.
        string[] ipAndPort = ip.Split(':', StringSplitOptions.RemoveEmptyEntries);
        ushort port = 30000;
        if (ipAndPort.Length > 1)
        {
            ip = ipAndPort[0];
            _ = ushort.TryParse(ipAndPort[1], out port);
        }

        // Initiate connection.
        TcpClient client = new();
        try
        {
            IPEndPoint endPoint = new(IPAddress.Parse(ip), port);
            client.Connect(endPoint);
        }
        catch (Exception)
        {
            Console.WriteLine($"Could not connect to server {ip}:{port}: either it is incorrect or no server is currently running with that port.");
            return 1;
        }

        // SSL authentication.
        NetworkStream stream = client.GetStream();
        sslStream = new(stream, false, VerifyCertificate, null);
        try
        {
            Console.Write($"Specify the name of the target host. If you have not been directed to one, leave this blank.\n>>> ");
            string? target = Console.ReadLine();
            if (target == null)
                return 1;
            sslStream.AuthenticateAsClient(target);
        }
        catch (AuthenticationException exception)
        {
            Console.WriteLine($"Failed to authenticate SSL connection: {exception.Message}");
            return 1;
        }

        // Start sending messages!
        Thread thread = new(ReadIncoming);
        thread.Start(client);
        SendToServer(name);
        Console.WriteLine($"Connected to server {ip}:{port}!");
        while (true)
        {
            initialHeight = Console.CursorTop;
            string? input = ReadLineAdjusted();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("You: ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(input);
            SendToServer(input);
        }
    }
}
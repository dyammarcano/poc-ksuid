using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1;

internal class Program
{
    private static void Main()
    {
        const ulong baseId = 1_000_000_000_000;
        const int total = 10;

        Thread[] threads = new Thread[total];

        for (int i = 0; i < total; i++)
        {
            int threadIndex = i; // capture the loop variable correctly for closure
            threads[i] = new Thread(() =>
            {
                ulong currentId = baseId + (ulong)threadIndex;
                string ksuid = Encoder.GenerateKsuid(currentId);
                var (decodedId, timestamp) = Encoder.DecodeKsuid(ksuid);

                lock (Console.Out) // ensure clean output
                {
                    Console.WriteLine($"[{threadIndex}] KSUID: {ksuid}");
                    Console.WriteLine($"    Original ID: {currentId}");
                    Console.WriteLine($"    Decoded ID:  {decodedId}");
                    Console.WriteLine($"    Timestamp:   {timestamp.ToUniversalTime():O}\n");
                }
            });

            threads[i].Start();
        }

        // Wait for all threads to complete
        foreach (var thread in threads)
        {
            thread.Join();
        }
    }

}

public static class Encoder
{
    private const int PayloadSize = 16;
    private const int IdSize = 6;
    private const string Base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static readonly DateTime KsuidEpoch = new(2014, 5, 13, 0, 0, 0, DateTimeKind.Utc);

    // 🛠️ Generate KSUID with injected ID
    public static string GenerateKsuid(ulong id)
    {
        // Convert to 8-byte buffer and take last 6 bytes (big-endian)
        var idBytesFull = BitConverter.GetBytes(id);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(idBytesFull);
        var idBytes = idBytesFull.Skip(2).ToArray(); // get last 6 bytes

        // Create payload: 6 bytes of ID + 10 random bytes
        var payload = new byte[PayloadSize];
        Array.Copy(idBytes, 0, payload, 0, IdSize);
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(payload, IdSize, PayloadSize - IdSize);
        }

        // 4-byte timestamp (big-endian)
        var timestamp = (uint)(DateTime.UtcNow - KsuidEpoch).TotalSeconds;
        var timestampBytes = BitConverter.GetBytes(timestamp);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);

        // Combine timestamp + payload
        var ksuidBytes = new byte[20];
        Array.Copy(timestampBytes, 0, ksuidBytes, 0, 4);
        Array.Copy(payload, 0, ksuidBytes, 4, PayloadSize);

        return Base62Encode(ksuidBytes).PadLeft(27, '0');
    }

    // 🔍 Decode KSUID into ID and timestamp
    public static (ulong id, DateTime timestamp) DecodeKsuid(string ksuid)
    {
        var data = Base62Decode(ksuid);
        if (data.Length != 20)
            throw new ArgumentException("Invalid KSUID: must decode to 20 bytes");

        // Extract timestamp
        var timestampBytes = data.Take(4).ToArray();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timestampBytes);
        var timestamp = BitConverter.ToUInt32(timestampBytes, 0);
        var dateTime = KsuidEpoch.AddSeconds(timestamp);

        // Extract ID from first 6 bytes of payload
        var payload = data.Skip(4).Take(PayloadSize).ToArray();
        var idBytes = new byte[8]; // 64-bit buffer
        Array.Copy(payload, 0, idBytes, 2, IdSize); // insert into last 6 bytes
        if (BitConverter.IsLittleEndian)
            Array.Reverse(idBytes);
        var id = BitConverter.ToUInt64(idBytes, 0);

        return (id, dateTime);
    }

    // 🔢 Base62 Encode
    private static string Base62Encode(byte[] data)
    {
        var value = new BigInteger(data.Reverse().Concat(new byte[] { 0 }).ToArray());
        var sb = new StringBuilder();
        while (value > 0)
        {
            value = BigInteger.DivRem(value, 62, out var rem);
            sb.Insert(0, Base62Chars[(int)rem]);
        }

        return sb.ToString();
    }

    // 🔢 Base62 Decode
    private static byte[] Base62Decode(string input)
    {
        var value = BigInteger.Zero;
        foreach (var c in input)
        {
            var index = Base62Chars.IndexOf(c);
            if (index == -1)
                throw new ArgumentException($"Invalid base62 character: '{c}'");
            value = value * 62 + index;
        }

        var bytes = value.ToByteArray().Reverse().ToArray();

        // Normalize to 20 bytes (KSUID spec)
        if (bytes.Length > 20)
            return bytes.Skip(bytes.Length - 20).ToArray();
        if (bytes.Length < 20)
            return Enumerable.Repeat((byte)0, 20 - bytes.Length).Concat(bytes).ToArray();

        return bytes;
    }
}

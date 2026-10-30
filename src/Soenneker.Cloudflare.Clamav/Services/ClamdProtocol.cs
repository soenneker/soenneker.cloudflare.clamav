using System;
using System.Buffers.Binary;
using System.IO;
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.Cloudflare.Clamav.Enums;
using Soenneker.Cloudflare.Clamav.Responses;
namespace Soenneker.Cloudflare.Clamav.Services;

/// <summary>Implements bounded, null-terminated ClamAV commands without parsing process exception messages.</summary>
public sealed class ClamdProtocol
{
    public async ValueTask<string> Command(int port, string command, CancellationToken token)
    {
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port, token);
        await using NetworkStream stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"z{command}\0"), token);
        return await ReadResponse(stream, token);
    }

    public async ValueTask<string> Scan(int port, string path, CancellationToken token)
    {
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port, token);
        await using NetworkStream stream = client.GetStream();
        await stream.WriteAsync("zINSTREAM\0"u8.ToArray(), token);
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous);
        byte[] buffer = new byte[65536];
        byte[] length = new byte[4];
        int count;
        while ((count = await input.ReadAsync(buffer, token)) > 0)
        {
            BinaryPrimitives.WriteInt32BigEndian(length, count);
            await stream.WriteAsync(length, token);
            await stream.WriteAsync(buffer.AsMemory(0, count), token);
        }
        await stream.WriteAsync(new byte[4], token);
        return await ReadResponse(stream, token);
    }

    private static async ValueTask<string> ReadResponse(Stream stream, CancellationToken token)
    {
        byte[] buffer = new byte[8192];
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), token);
            if (read == 0) throw new IOException("The scanner closed its connection without a complete response.");
            int end = Array.IndexOf(buffer, (byte)0, offset, read);
            if (end >= 0) return Encoding.UTF8.GetString(buffer, 0, end);
            offset += read;
        }
        throw new InvalidDataException("The scanner response exceeded its limit.");
    }

    public static HealthResponse ParseVersion(string version, DateTimeOffset now, TimeSpan maximumAge, DateTimeOffset? lastUpdate)
    {
        string[] parts = version.Split('/');
        if (parts.Length != 3 || !parts[0].StartsWith("ClamAV ", StringComparison.Ordinal) ||
            !long.TryParse(parts[1], CultureInfo.InvariantCulture, out _) ||
            !DateTimeOffset.TryParseExact(parts[2].Trim(),
                new[] { "ddd MMM d HH:mm:ss yyyy", "ddd MMM  d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy" },
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset date))
            return new(false, LastUpdateAt: lastUpdate);
        TimeSpan age = now - date;
        return new(age >= TimeSpan.FromMinutes(-5) && age <= maximumAge, parts[0], parts[1], date, lastUpdate);
    }

    public static VirusScanResponse Parse(string response)
    {
        if (response == "stream: OK") return new(true, null, "ClamAV");
        if (response.Contains('\n') || response.Contains('\r') || !response.StartsWith("stream: ", StringComparison.Ordinal) || !response.EndsWith(" FOUND", StringComparison.Ordinal))
            return new(false, null, "ClamAV") { Verdict = ScanVerdict.Error.Value, Reason = ScanReason.EngineError.Value };
        string signature = response[8..^6];
        if (string.IsNullOrWhiteSpace(signature))
            return new(false, null, "ClamAV") { Verdict = ScanVerdict.Error.Value, Reason = ScanReason.EngineError.Value };
        string? reason = signature.StartsWith("Heuristics.Limits.Exceeded", StringComparison.Ordinal) ? ScanReason.InspectionLimit.Value :
            signature.StartsWith("Heuristics.Encrypted", StringComparison.Ordinal) ? ScanReason.Encrypted.Value :
            signature.StartsWith("Heuristics.Broken", StringComparison.Ordinal) ? ScanReason.Unsupported.Value : null;
        return new(false, signature, "ClamAV")
        {
            Verdict = reason is null ? ScanVerdict.Infected.Value : ScanVerdict.Inconclusive.Value,
            Reason = reason ?? ScanReason.ThreatDetected.Value
        };
    }
}

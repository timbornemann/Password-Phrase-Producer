using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;

namespace Password_Phrase_Producer.Services.LocalTransfer;

internal sealed record LocalTransferTicket(IPAddress Address, int Port, string Phrase, Guid? SessionId = null)
{
    private const string Prefix = "ppp-transfer:v1:";

    internal string ToQrText()
    {
        if (SessionId is null || !LocalTransferAddresses.IsPrivate(Address) || Port is < 1 or > 65535 ||
            !AdaptiveDicewareTechnique.TryNormalizeSessionPhrase(Phrase, out var normalized))
            throw new InvalidDataException("Ungültiger lokaler Transfercode.");
        var json = JsonSerializer.SerializeToUtf8Bytes(new TicketData(1, Address.ToString(), Port,
            normalized, SessionId.Value));
        return Prefix + Convert.ToBase64String(json).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    internal static LocalTransferTicket ParseQrText(string? text)
    {
        if (text is null || text.Length > 1024 || !text.StartsWith(Prefix, StringComparison.Ordinal))
            throw new InvalidDataException("Der QR-Code ist kein lokaler Transfercode.");
        try
        {
            var encoded = text[Prefix.Length..].Replace('-', '+').Replace('_', '/');
            var bytes = Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '='));
            var data = JsonSerializer.Deserialize<TicketData>(bytes)
                       ?? throw new InvalidDataException("Ungültiger Transfercode.");
            if (data.Version != 1 || data.SessionId == Guid.Empty)
                throw new InvalidDataException("Nicht unterstützter Transfercode.");
            return ParseManual(data.Address, data.Port.ToString(), data.Phrase, data.SessionId);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException)
        {
            throw new InvalidDataException("Ungültiger Transfercode.", ex);
        }
    }

    internal static LocalTransferTicket ParseManual(string? address, string? port, string? phrase,
        Guid? sessionId = null)
    {
        if (!IPAddress.TryParse(address, out var ip) || !LocalTransferAddresses.IsPrivate(ip) ||
            !int.TryParse(port, out var number) || number is < 1 or > 65535 ||
            !AdaptiveDicewareTechnique.TryNormalizeSessionPhrase(phrase, out var normalized))
            throw new InvalidDataException("Bitte private LAN-IP, Port und sechs gültige Wörter eingeben.");
        return new LocalTransferTicket(ip, number, normalized, sessionId);
    }

    private sealed record TicketData(int Version, string Address, int Port, string Phrase, Guid SessionId);
}

internal static class LocalTransferAddresses
{
    internal static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
               bytes[0] == 192 && bytes[1] == 168;
    }

    internal static IReadOnlyList<IPAddress> Find()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                              adapter.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Select(item => item.Address)
            .Where(IsPrivate)
            .Distinct()
            .OrderBy(address => address.ToString(), StringComparer.Ordinal)
            .ToArray();
    }
}

using Soenneker.Gen.EnumValues;
namespace Soenneker.Cloudflare.Clamav.Enums;

/// <summary>Distinguishes completed inspection from threats and incomplete inspection.</summary>
[EnumValue<string>]
public sealed partial class ScanVerdict
{
    public static readonly ScanVerdict Clean = new("clean");
    public static readonly ScanVerdict Infected = new("infected");
    public static readonly ScanVerdict Inconclusive = new("inconclusive");
    public static readonly ScanVerdict Error = new("error");
}

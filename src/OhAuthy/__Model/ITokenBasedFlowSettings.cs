namespace Ww.OhAuthy;

using KeyValue = KeyValuePair<string, string?>;

public interface ITokenBasedFlowSettings
{
    string TokenUrl { get; }

    IEnumerable<KeyValue> CreateParameters();
    IEnumerable<KeyValue> CreateHeaders();
}

using System.Diagnostics;

namespace Ww.OhAuthy;

public sealed class WindowsPlatformProxy : IPlatformProxy
{
    public Task StartDefaultOsBrowserAsync(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to launch the default browser. See inner exception for details.", ex);
        }
        return Task.CompletedTask;
    }
}

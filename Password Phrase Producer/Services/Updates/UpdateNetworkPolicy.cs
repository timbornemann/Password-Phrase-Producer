using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer.Services.Updates;

public sealed class UpdateNetworkPolicy : IUpdateNetworkPolicy
{
    public event EventHandler? Changed;
    public bool HasInternet => Connectivity.Current.NetworkAccess == NetworkAccess.Internet;
    public bool IsUnmetered
    {
        get
        {
            if (!HasInternet) return false;
            try
            {
#if WINDOWS
                var profile = global::Windows.Networking.Connectivity.NetworkInformation.GetInternetConnectionProfile();
                var cost = profile?.GetConnectionCost();
                return profile is not null && !profile.IsWwanConnectionProfile && cost is not null &&
                    cost.NetworkCostType == global::Windows.Networking.Connectivity.NetworkCostType.Unrestricted &&
                    !cost.Roaming && !cost.OverDataLimit && !cost.ApproachingDataLimit;
#elif ANDROID
                var manager = (global::Android.Net.ConnectivityManager?)global::Android.App.Application.Context
                    .GetSystemService(global::Android.Content.Context.ConnectivityService);
                return manager is not null && !manager.IsActiveNetworkMetered &&
                    !Connectivity.Current.ConnectionProfiles.Contains(ConnectionProfile.Cellular);
#else
                return false;
#endif
            }
            catch { return false; } // Unknown cost is never treated as unmetered.
        }
    }

#if ANDROID
    private readonly NetworkObserver? _observer;
#endif

    public UpdateNetworkPolicy()
    {
        Connectivity.Current.ConnectivityChanged += (_, _) => Changed?.Invoke(this, EventArgs.Empty);
#if WINDOWS
        global::Windows.Networking.Connectivity.NetworkInformation.NetworkStatusChanged +=
            _ => Changed?.Invoke(this, EventArgs.Empty);
#elif ANDROID
        var manager = (global::Android.Net.ConnectivityManager?)global::Android.App.Application.Context
            .GetSystemService(global::Android.Content.Context.ConnectivityService);
        if (manager is not null)
        {
            _observer = new NetworkObserver(() => Changed?.Invoke(this, EventArgs.Empty));
            if (global::Android.OS.Build.VERSION.SdkInt >= global::Android.OS.BuildVersionCodes.N)
                manager.RegisterDefaultNetworkCallback(_observer);
            else
            {
                using var request = new global::Android.Net.NetworkRequest.Builder()
                    .AddCapability(global::Android.Net.NetCapability.Internet)!.Build()!;
                manager.RegisterNetworkCallback(request, _observer);
            }
        }
#endif
    }

#if ANDROID
    private sealed class NetworkObserver(Action changed) : global::Android.Net.ConnectivityManager.NetworkCallback
    {
        public override void OnCapabilitiesChanged(global::Android.Net.Network network, global::Android.Net.NetworkCapabilities capabilities) => changed();
        public override void OnLost(global::Android.Net.Network network) => changed();
    }
#endif
}

public sealed class UpdateStorageSpace : IStorageSpace
{
    public long AvailableBytes(string directory)
    {
#if ANDROID
        using var stat = new global::Android.OS.StatFs(directory);
        return stat.AvailableBytes;
#else
        return new DiskStorageSpace().AvailableBytes(directory);
#endif
    }
}

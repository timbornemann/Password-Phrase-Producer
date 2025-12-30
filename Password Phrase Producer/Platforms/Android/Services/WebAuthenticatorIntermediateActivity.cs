using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;

namespace Password_Phrase_Producer.Platforms.Android.Services;

[Activity(LaunchMode = LaunchMode.SingleTop)]
public class WebAuthenticatorIntermediateActivity : Activity
{
    public static Action<string?>? Callback;
    private const int RequestCode = 1001;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Prevent restarting the picker on configuration changes if already started
        if (savedInstanceState != null) return;

        Intent? originalIntent = null;
        
        // Android 13+ (API 33+)
        if (Build.VERSION.SdkInt >= BuildVersionCodes.Tiramisu)
        {
            originalIntent = Intent?.GetParcelableExtra("OriginalIntent", Java.Lang.Class.FromType(typeof(Intent))) as Intent;
        }
        else
        {
            originalIntent = Intent?.GetParcelableExtra("OriginalIntent") as Intent;
        }

        if (originalIntent != null)
        {
            StartActivityForResult(originalIntent, RequestCode);
        }
        else
        {
            // Failed to extract intent, ensure we don't hang
            Callback?.Invoke(null);
            Finish();
        }
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);

        if (requestCode == RequestCode)
        {
            if (resultCode == Result.Ok && data?.Data != null)
            {
                var uri = data.Data;
                try 
                {
                    var takeFlags = ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission;
                    ContentResolver?.TakePersistableUriPermission(uri, takeFlags);
                }
                catch 
                { 
                    // Log or ignore if not supported
                }
                
                Callback?.Invoke(uri.ToString());
            }
            else
            {
                // Cancelled or failed
                Callback?.Invoke(null);
            }
        }
        
        Finish();
    }
}

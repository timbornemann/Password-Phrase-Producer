using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;

namespace Password_Phrase_Producer.Platforms.Android.Services;

[Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop)]
public class WebAuthenticatorIntermediateActivity : Activity
{
    public static Action<string?>? Callback;
    private const int RequestCode = 1001;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        var originalIntent = Intent?.GetParcelableExtra("OriginalIntent", Java.Lang.Class.FromType(typeof(Intent))) as Intent;
        
        // On older Android versions, or generic fallback
        if (originalIntent == null) 
             originalIntent = Intent?.GetParcelableExtra("OriginalIntent") as Intent;

        if (originalIntent != null)
        {
            StartActivityForResult(originalIntent, RequestCode);
        }
        else
        {
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
                Callback?.Invoke(data.Data.ToString());
            }
            else
            {
                Callback?.Invoke(null);
            }
        }
        
        Finish();
    }
}

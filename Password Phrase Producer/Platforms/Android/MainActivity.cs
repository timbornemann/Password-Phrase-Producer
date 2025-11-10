using System;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;

namespace Password_Phrase_Producer
{
    [Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTop, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
    public class MainActivity : MauiAppCompatActivity
    {
        public static MainActivity? Current { get; private set; }

        public event EventHandler<ActivityResultEventArgs>? ActivityResult;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            Current = this;
        }

        protected override void OnDestroy()
        {
            if (ReferenceEquals(Current, this))
            {
                Current = null;
            }

            base.OnDestroy();
        }

        protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
        {
#pragma warning disable CA1416
            base.OnActivityResult(requestCode, resultCode, data);
#pragma warning restore CA1416
            ActivityResult?.Invoke(this, new ActivityResultEventArgs(requestCode, resultCode, data));
        }
    }

    public sealed class ActivityResultEventArgs : EventArgs
    {
        public ActivityResultEventArgs(int requestCode, Result resultCode, Intent? data)
        {
            RequestCode = requestCode;
            ResultCode = resultCode;
            Data = data;
        }

        public int RequestCode { get; }

        public Result ResultCode { get; }

        public Intent? Data { get; }
    }
}

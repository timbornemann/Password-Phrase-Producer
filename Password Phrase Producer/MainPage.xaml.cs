using Password_Phrase_Producer.Password_generation_techniques.tbv_techniques;

namespace Password_Phrase_Producer
{
    public partial class MainPage : ContentPage
    {
        int count = 0;

        public MainPage()
        {
            InitializeComponent();
        }

        private void Button_Clicked(object sender, EventArgs e)
        {
            TBV1WithErrors tbv1 = new TBV1WithErrors();
            string password = PasswordField.Text;
            int code1 = int.Parse(Code1Field.Text);
            int code2 = int.Parse(Code2Field.Text);
            int code3 = int.Parse(Code3Field.Text);
            ResultField.Text = tbv1.Encrypt(password, code1, code2, code3);

        }
    }

}

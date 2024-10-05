using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.Windows;
using PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer
{
    public partial class MainPage : ContentPage
    {
        

        TbvUiPage TBVUiPage;

        public MainPage()
        {
            InitializeComponent();
        }




        private void OnMenuClicked(object sender, EventArgs e)
        {
            ShowMenuButtons();
            if (this.TBVUiPage != null)
            {
                Content.Remove(this.TBVUiPage);
            }
        }

        private void OnAlternateWordsClicked(object sender, EventArgs e)
        {
            HideMenuButtons();
        }

        private void OnTBV1WithErrorsClicked(object sender, EventArgs e)
        {
            HideMenuButtons();

            this.TBVUiPage = new TBVUiPage(new TBV1WithErrors());
            Content.Add(this.TBVUiPage);
        }

        private void OnTBV1Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TBVUiPage = new TBVUiPage(new TBV1());
            Content.Add(this.TBVUiPage);
        }

        private void OnTBV2Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TBVUiPage = new TBVUiPage(new TBV2());
            Content.Add(this.TBVUiPage);
        }

        private void OnTBV3Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TBVUiPage = new TBVUiPage(new TBV3());
            Content.Add(this.TBVUiPage);
        }

        public void HideMenuButtons()
        {
            L1.IsVisible = false;
            B1.IsVisible = false;
            B2.IsVisible = false;
            B3.IsVisible = false;
            B4.IsVisible = false;
            B5.IsVisible = false;
        }

        public void ShowMenuButtons()
        {
            L1.IsVisible = true;
            B1.IsVisible = true;
            B2.IsVisible = true;
            B3.IsVisible = true;
            B4.IsVisible = true;
            B5.IsVisible = true;
        }


    }

}

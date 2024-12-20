﻿using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using Password_Phrase_Producer.Windows.PasswordGenerationWindows;
using PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer
{
    public partial class MainPage : ContentPage
    {
        

        TbvUiPage TbvUiPage;
        ConcatenationTechniquesUiPage ConcatenationTechniquesUiPage;
        HachBasedTechniquesUiPage HachBasedTechniquesUiPage;
        public MainPage()
        {
            InitializeComponent();
        }

        private void OnMenuClicked(object sender, EventArgs e)
        {
            ShowMenuButtons();
            if (this.TbvUiPage != null)
            {
                Content.Remove(this.TbvUiPage);
                this.TbvUiPage = null;
            }
            if(this.ConcatenationTechniquesUiPage != null)
            {
                Content.Remove(this.ConcatenationTechniquesUiPage);
                this.ConcatenationTechniquesUiPage = null;
            }

            if (this.HachBasedTechniquesUiPage != null)
            {
                Content.Remove(this.HachBasedTechniquesUiPage);
                this.HachBasedTechniquesUiPage = null;
            }
        }

        private void OnAlternateWordsClicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.ConcatenationTechniquesUiPage = new ConcatenationTechniquesUiPage(new AlternatingUpDownChaining());
            Content.Add(this.ConcatenationTechniquesUiPage);
        }

        private void OneWordPasswordClicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.HachBasedTechniquesUiPage = new HachBasedTechniquesUiPage(new DeterministicHashPasswordGenerator());
            Content.Add(this.HachBasedTechniquesUiPage);
        }



        private void OnTBV1WithErrorsClicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TbvUiPage = new TbvUiPage(new TBV1WithErrors());
            Content.Add(this.TbvUiPage);          
        }

        private void OnTBV1Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TbvUiPage = new TbvUiPage(new TBV1());
            Content.Add(this.TbvUiPage);
        }

        private void OnTBV2Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TbvUiPage = new TbvUiPage(new TBV2());
            Content.Add(this.TbvUiPage);
        }

        private void OnTBV3Clicked(object sender, EventArgs e)
        {
            HideMenuButtons();
            this.TbvUiPage = new TbvUiPage(new TBV3());
            Content.Add(this.TbvUiPage);
        }

        public void HideMenuButtons()
        {
            L1.IsVisible = false;
            B1.IsVisible = false;
            B2.IsVisible = false;
            B3.IsVisible = false;
            B4.IsVisible = false;
            B5.IsVisible = false;
            B6.IsVisible = false;
        }

        public void ShowMenuButtons()
        {
            L1.IsVisible = true;
            B1.IsVisible = true;
            B2.IsVisible = true;
            B3.IsVisible = true;
            B4.IsVisible = true;
            B5.IsVisible = true;
            B6.IsVisible = true;
        }
    }

}

using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer.Windows;

public class TbvUiPage : ContentView
{
	Itbv tbv;
	public TbvUiPage(Itbv itbv)
	{
		this.tbv = itbv;
		Content = new VerticalStackLayout
		{
			Children = {
				new Label { HorizontalOptions = LayoutOptions.Center, VerticalOptions = LayoutOptions.Center, Text = "Welcome to .NET MAUI!"
				}
			}
		};
	}
}
using System;
using System.Collections.Generic;
using Microsoft.Maui.Controls;
using PasswordModeOption = Password_Phrase_Producer.PasswordModeOption;

namespace Password_Phrase_Producer.Views;

public partial class ModeHostPage : ContentPage
{
    public ModeHostPage(PasswordModeOption option)
    {
        InitializeComponent();
        BindingContext = option;
        Title = option.Title;
        var contentView = option.CreateView();
        ContentHost.Content = new PasswordGeneratorHostView(contentView);
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        ClearAllInputFields();
        await NavigateBackAsync();
    }

    private void OnOpenMenuTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }

    protected override bool OnBackButtonPressed()
    {
        ClearAllInputFields();
        Dispatcher.Dispatch(async () => await NavigateBackAsync());
        return true;
    }

    private void ClearAllInputFields()
    {
        if (ContentHost?.Content is null)
        {
            return;
        }

        // ContentHost.Content is a PasswordGeneratorHostView, we need to find the actual content inside it
        View? actualContent = ContentHost.Content;
        
        // Navigate through PasswordGeneratorHostView structure
        // PasswordGeneratorHostView is a ContentView that contains a Grid
        if (actualContent is ContentView hostView && hostView.Content is View innerContent)
        {
            actualContent = innerContent;
            
            // If innerContent is a Grid, find the actual generator page content (first child)
            if (innerContent is Grid grid && grid.Children.Count > 0)
            {
                // The first child is usually the actual generator page content
                var firstChild = grid.Children[0];
                if (firstChild is View generatorView)
                {
                    actualContent = generatorView;
                }
            }
        }

        // Find all Entry fields recursively and clear them
        var entries = FindAllEntries(actualContent);
        foreach (var entry in entries)
        {
            entry.Text = string.Empty;
        }

        // Reset CheckBoxes to default state (usually true for most)
        var checkBoxes = FindCheckBoxes(actualContent);
        foreach (var checkBox in checkBoxes)
        {
            // Try to get name from StyleId, AutomationId, or via reflection
            var name = checkBox.StyleId ?? checkBox.AutomationId ?? string.Empty;
            if (string.IsNullOrEmpty(name))
            {
                // Try to get name via reflection (for x:Name in XAML)
                var nameProperty = checkBox.GetType().GetProperty("Name");
                if (nameProperty != null)
                {
                    name = nameProperty.GetValue(checkBox)?.ToString() ?? string.Empty;
                }
            }

            var nameLower = name.ToLowerInvariant();
            if (nameLower.Contains("uppercase") || nameLower.Contains("lowercase") || nameLower.Contains("digits"))
            {
                checkBox.IsChecked = true;
            }
            else if (nameLower.Contains("special"))
            {
                checkBox.IsChecked = true; // Default to true
            }
            else
            {
                checkBox.IsChecked = false; // Default for other checkboxes
            }
        }

        // Reset Sliders to default values
        var sliders = FindSliders(actualContent);
        foreach (var slider in sliders)
        {
            // Reset to minimum value or a reasonable default
            slider.Value = slider.Minimum;
        }

        // Clear analysis panel if it exists
        ClearAnalysisPanel(actualContent);
    }

    private static List<Entry> FindAllEntries(View? view)
    {
        var entries = new List<Entry>();
        if (view is null)
        {
            return entries;
        }

        // If this is an Entry, add it to the list
        if (view is Entry entry)
        {
            entries.Add(entry);
        }

        // Recursively search children
        if (view is Layout layout)
        {
            foreach (var child in layout.Children)
            {
                if (child is View childView)
                {
                    entries.AddRange(FindAllEntries(childView));
                }
            }
        }
        else if (view is ContentView contentView && contentView.Content is View content)
        {
            entries.AddRange(FindAllEntries(content));
        }
        else if (view is ScrollView scrollView && scrollView.Content is View scrollContent)
        {
            entries.AddRange(FindAllEntries(scrollContent));
        }
        else if (view is Border border && border.Content is View borderContent)
        {
            entries.AddRange(FindAllEntries(borderContent));
        }
        else if (view is Microsoft.Maui.Controls.Element element)
        {
            // Try to find children via LogicalChildren for other view types
            foreach (var child in element.LogicalChildren)
            {
                if (child is View childView)
                {
                    entries.AddRange(FindAllEntries(childView));
                }
            }
        }

        return entries;
    }

    private static List<Entry> FindEntriesByName(View? view, string name)
    {
        var entries = new List<Entry>();
        if (view is null)
        {
            return entries;
        }

        if (view is Entry entry)
        {
            var entryName = entry.StyleId ?? entry.AutomationId ?? string.Empty;
            if (string.IsNullOrEmpty(entryName))
            {
                // Try to get name via reflection (for x:Name in XAML)
                var nameProperty = entry.GetType().GetProperty("Name");
                if (nameProperty != null)
                {
                    entryName = nameProperty.GetValue(entry)?.ToString() ?? string.Empty;
                }
            }
            if (entryName == name)
            {
                entries.Add(entry);
            }
        }

        // Recursively search children
        if (view is Layout layout)
        {
            foreach (var child in layout.Children)
            {
                if (child is View childView)
                {
                    entries.AddRange(FindEntriesByName(childView, name));
                }
            }
        }
        else if (view is ContentView contentView && contentView.Content is View content)
        {
            entries.AddRange(FindEntriesByName(content, name));
        }
        else if (view is ScrollView scrollView && scrollView.Content is View scrollContent)
        {
            entries.AddRange(FindEntriesByName(scrollContent, name));
        }

        return entries;
    }

    private static void ClearAnalysisPanel(View? view)
    {
        if (view is null)
        {
            return;
        }

        // Try to find analysis panel and reset it
        if (view is Microsoft.Maui.Controls.Element element)
        {
            // Look for analysisPanel by name or type
            var analysisPanel = FindViewByName(element, "analysisPanel");
            if (analysisPanel is not null)
            {
                // Try to call Reset method if it exists
                var resetMethod = analysisPanel.GetType().GetMethod("Reset");
                resetMethod?.Invoke(analysisPanel, null);
            }
        }
    }

    private static List<CheckBox> FindCheckBoxes(View? view)
    {
        var checkBoxes = new List<CheckBox>();
        if (view is null)
        {
            return checkBoxes;
        }

        if (view is CheckBox checkBox)
        {
            checkBoxes.Add(checkBox);
        }

        // Recursively search children
        if (view is Layout layout)
        {
            foreach (var child in layout.Children)
            {
                if (child is View childView)
                {
                    checkBoxes.AddRange(FindCheckBoxes(childView));
                }
            }
        }
        else if (view is ContentView contentView && contentView.Content is View content)
        {
            checkBoxes.AddRange(FindCheckBoxes(content));
        }
        else if (view is ScrollView scrollView && scrollView.Content is View scrollContent)
        {
            checkBoxes.AddRange(FindCheckBoxes(scrollContent));
        }
        else if (view is Border border && border.Content is View borderContent)
        {
            checkBoxes.AddRange(FindCheckBoxes(borderContent));
        }
        else if (view is Microsoft.Maui.Controls.Element element)
        {
            foreach (var child in element.LogicalChildren)
            {
                if (child is View childView)
                {
                    checkBoxes.AddRange(FindCheckBoxes(childView));
                }
            }
        }

        return checkBoxes;
    }

    private static List<Slider> FindSliders(View? view)
    {
        var sliders = new List<Slider>();
        if (view is null)
        {
            return sliders;
        }

        if (view is Slider slider)
        {
            sliders.Add(slider);
        }

        // Recursively search children
        if (view is Layout layout)
        {
            foreach (var child in layout.Children)
            {
                if (child is View childView)
                {
                    sliders.AddRange(FindSliders(childView));
                }
            }
        }
        else if (view is ContentView contentView && contentView.Content is View content)
        {
            sliders.AddRange(FindSliders(content));
        }
        else if (view is ScrollView scrollView && scrollView.Content is View scrollContent)
        {
            sliders.AddRange(FindSliders(scrollContent));
        }
        else if (view is Border border && border.Content is View borderContent)
        {
            sliders.AddRange(FindSliders(borderContent));
        }
        else if (view is Microsoft.Maui.Controls.Element element)
        {
            foreach (var child in element.LogicalChildren)
            {
                if (child is View childView)
                {
                    sliders.AddRange(FindSliders(childView));
                }
            }
        }

        return sliders;
    }

    private static View? FindViewByName(Microsoft.Maui.Controls.Element? element, string name)
    {
        if (element is null)
        {
            return null;
        }

        if (element is View view)
        {
            var viewName = view.StyleId ?? view.AutomationId ?? string.Empty;
            if (string.IsNullOrEmpty(viewName))
            {
                // Try to get name via reflection (for x:Name in XAML)
                var nameProperty = view.GetType().GetProperty("Name");
                if (nameProperty != null)
                {
                    viewName = nameProperty.GetValue(view)?.ToString() ?? string.Empty;
                }
            }
            if (viewName == name)
            {
                return view;
            }
        }

        // Recursively search children
        foreach (var child in element.LogicalChildren)
        {
            if (child is Microsoft.Maui.Controls.Element childElement)
            {
                var result = FindViewByName(childElement, name);
                if (result is not null)
                {
                    return result;
                }
            }
        }

        return null;
    }

    private async System.Threading.Tasks.Task NavigateBackAsync()
    {
        if (Shell.Current is null)
        {
            return;
        }

        // Navigate back to generation methods page (modus overview)
        // This is the page where users select which mode to use
        try
        {
            await Shell.Current.GoToAsync("//generate");
        }
        catch
        {
            // Fallback to home if navigation fails
            await Shell.Current.GoToAsync("//home");
        }
    }
}

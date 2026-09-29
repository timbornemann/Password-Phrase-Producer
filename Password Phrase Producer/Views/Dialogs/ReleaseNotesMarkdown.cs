using Markdig;
using Markdig.Extensions.Tables;
using Markdig.Extensions.TaskLists;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using Microsoft.Maui.Controls.Shapes;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// Renders signed release notes as native views. Raw HTML in the Markdown is disabled.
/// </summary>
internal static class ReleaseNotesMarkdown
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UseAdvancedExtensions()
        .UseSoftlineBreakAsHardlineBreak()
        .DisableHtml()
        .Build();

    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#E8EBFF");
    private static readonly Color TextTertiary = Color.FromArgb("#9EA3C4");
    private static readonly Color LinkColor = Color.FromArgb("#9AABFF");
    private static readonly Color CodeBackground = Color.FromArgb("#262D4A");
    private static readonly Color QuoteBackground = Color.FromArgb("#222846");
    private static readonly Color RuleColor = Color.FromArgb("#3A4068");

    private readonly record struct InlineStyle(FontAttributes Attributes, TextDecorations Decorations, Color Color, double FontSize);

    public static View Render(string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return EmptyLabel();

        try
        {
            var document = Markdown.Parse(markdown, Pipeline);
            var stack = new VerticalStackLayout { Spacing = 10, Padding = new Thickness(0, 0, 0, 4) };
            foreach (var block in document)
                RenderBlock(stack, block, depth: 0);
            return stack.Children.Count == 0 ? EmptyLabel() : stack;
        }
        catch (Exception)
        {
            return PlainLabel(markdown.Trim());
        }
    }

    private static void RenderBlock(VerticalStackLayout parent, Block block, int depth)
    {
        switch (block)
        {
            case HeadingBlock heading:
                AddFormatted(parent, heading, HeadingStyle(heading.Level));
                break;
            case ParagraphBlock paragraph:
                AddFormatted(parent, paragraph, BodyStyle(), skipTaskMarker: true);
                break;
            case ListBlock list:
                parent.Children.Add(RenderList(list, depth));
                break;
            case QuoteBlock quote:
                parent.Children.Add(RenderQuote(quote, depth));
                break;
            case CodeBlock code:
                parent.Children.Add(RenderCode(code));
                break;
            case ThematicBreakBlock:
                parent.Children.Add(new BoxView
                {
                    HeightRequest = 1,
                    Color = RuleColor,
                    HorizontalOptions = LayoutOptions.Fill,
                    Margin = new Thickness(0, 4)
                });
                break;
            case Table table:
                parent.Children.Add(RenderTable(table));
                break;
            case LinkReferenceDefinitionGroup:
                break;
            default:
                var plain = PlainText(block).Trim();
                if (plain.Length > 0)
                    parent.Children.Add(PlainLabel(plain));
                break;
        }
    }

    private static View RenderList(ListBlock list, int depth)
    {
        var stack = new VerticalStackLayout
        {
            Spacing = 8,
            Margin = new Thickness(depth > 0 ? 12 : 0, 0, 0, 0)
        };
        var index = 0;
        foreach (var item in list)
        {
            if (item is not ListItemBlock listItem)
                continue;

            var content = new VerticalStackLayout { Spacing = 6 };
            foreach (var child in listItem)
                RenderBlock(content, child, depth + 1);

            var row = new Grid
            {
                ColumnDefinitions =
                {
                    new ColumnDefinition { Width = GridLength.Auto },
                    new ColumnDefinition { Width = new GridLength(8) },
                    new ColumnDefinition { Width = GridLength.Star }
                },
                ColumnSpacing = 0
            };
            var marker = new Label
            {
                Text = ListMarker(list, listItem, index),
                TextColor = TextSecondary,
                FontSize = 14,
                VerticalOptions = LayoutOptions.Start
            };
            row.Children.Add(marker);
            Grid.SetColumn(content, 2);
            row.Children.Add(content);
            stack.Children.Add(row);
            index++;
        }

        return stack;
    }

    private static string ListMarker(ListBlock list, ListItemBlock item, int index)
    {
        var task = TaskMarker(item);
        if (task is not null)
            return task.Checked ? "☑" : "☐";
        if (list.IsOrdered)
            return $"{(item.Order > 0 ? item.Order : index + 1)}.";
        return "•";
    }

    private static TaskList? TaskMarker(ListItemBlock item)
    {
        if (item.Count == 0 || item[0] is not ParagraphBlock paragraph)
            return null;
        return paragraph.Inline?.FirstChild as TaskList;
    }

    private static View RenderQuote(QuoteBlock quote, int depth)
    {
        var stack = new VerticalStackLayout { Spacing = 8 };
        foreach (var child in quote)
            RenderBlock(stack, child, depth);
        return new Border
        {
            BackgroundColor = QuoteBackground,
            StrokeThickness = 0,
            StrokeShape = new RoundRectangle { CornerRadius = 8 },
            Padding = new Thickness(12, 8),
            Content = stack
        };
    }

    private static View RenderCode(CodeBlock block)
    {
        var stack = new VerticalStackLayout { Spacing = 4 };
        if (block is FencedCodeBlock { Info: { } info } && !string.IsNullOrWhiteSpace(info))
        {
            stack.Children.Add(new Label
            {
                Text = info.Trim(),
                FontSize = 11,
                TextColor = TextTertiary
            });
        }

        stack.Children.Add(new Label
        {
            Text = block.Lines.ToString().TrimEnd(),
            FontFamily = MonospaceFont(),
            FontSize = 13,
            TextColor = TextSecondary,
            LineBreakMode = LineBreakMode.CharacterWrap
        });

        return new Border
        {
            BackgroundColor = CodeBackground,
            StrokeThickness = 0,
            StrokeShape = new RoundRectangle { CornerRadius = 8 },
            Padding = new Thickness(10, 8),
            Content = stack
        };
    }

    private static View RenderTable(Table table)
    {
        var columnCount = table.ColumnDefinitions?.Count ?? 0;
        foreach (var row in table)
        {
            if (row is TableRow tableRow)
                columnCount = Math.Max(columnCount, tableRow.Count);
        }

        columnCount = Math.Max(columnCount, 1);
        var grid = new Grid { ColumnSpacing = 10, RowSpacing = 6 };
        for (var column = 0; column < columnCount; column++)
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Star });

        var rowIndex = 0;
        foreach (var row in table)
        {
            if (row is not TableRow tableRow)
                continue;

            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var columnIndex = 0;
            foreach (var cell in tableRow)
            {
                if (cell is not TableCell tableCell)
                    continue;

                var content = new VerticalStackLayout { Spacing = 4 };
                foreach (var child in tableCell)
                {
                    if (tableRow.IsHeader && child is ParagraphBlock paragraph)
                        AddFormatted(content, paragraph, HeadingStyle(4));
                    else
                        RenderBlock(content, child, depth: 0);
                }

                Grid.SetRow(content, rowIndex);
                Grid.SetColumn(content, columnIndex);
                if (tableCell.ColumnSpan > 1)
                    Grid.SetColumnSpan(content, tableCell.ColumnSpan);
                grid.Children.Add(content);
                columnIndex += Math.Max(1, tableCell.ColumnSpan);
            }

            rowIndex++;
        }

        return new Border
        {
            BackgroundColor = CodeBackground,
            StrokeThickness = 0,
            StrokeShape = new RoundRectangle { CornerRadius = 8 },
            Padding = new Thickness(10, 8),
            Content = grid
        };
    }

    private static void AddFormatted(VerticalStackLayout parent, LeafBlock block, InlineStyle style, bool skipTaskMarker = false)
    {
        var text = RenderInlines(block.Inline, style, skipTaskMarker);
        if (IsBlank(text))
        {
            var plain = block.Lines.ToString().Trim();
            if (plain.Length == 0)
                return;
            text = new FormattedString { Spans = { SpanFor(plain, style) } };
        }

        parent.Children.Add(new Label
        {
            FormattedText = text,
            LineBreakMode = LineBreakMode.WordWrap,
            HorizontalOptions = LayoutOptions.Fill
        });
    }

    private static FormattedString RenderInlines(ContainerInline? inline, InlineStyle style, bool skipTaskMarker = false)
    {
        var text = new FormattedString();
        if (inline is null)
            return text;

        var child = inline.FirstChild;
        if (skipTaskMarker && child is TaskList)
        {
            child = child.NextSibling;
            if (child is LiteralInline literal)
            {
                var literalText = literal.Content.ToString();
                if (literalText.StartsWith(' '))
                    literalText = literalText[1..];
                if (literalText.Length > 0)
                    text.Spans.Add(SpanFor(literalText, style));
                child = child.NextSibling;
            }
        }

        for (; child is not null; child = child.NextSibling)
            AppendInline(text, child, style);
        return text;
    }

    private static void AppendChildren(FormattedString target, ContainerInline container, InlineStyle style)
    {
        for (var child = container.FirstChild; child is not null; child = child.NextSibling)
            AppendInline(target, child, style);
    }

    private static void AppendInline(FormattedString target, Inline inline, InlineStyle style)
    {
        switch (inline)
        {
            case LiteralInline literal:
                var literalText = literal.Content.ToString();
                if (literalText.Length > 0)
                    target.Spans.Add(SpanFor(literalText, style));
                break;
            case CodeInline code:
                target.Spans.Add(new Span
                {
                    Text = code.Content ?? "",
                    FontFamily = MonospaceFont(),
                    FontSize = Math.Max(12, style.FontSize - 1),
                    TextColor = TextSecondary,
                    BackgroundColor = CodeBackground
                });
                break;
            case LineBreakInline:
                target.Spans.Add(SpanFor("\n", style));
                break;
            case HtmlEntityInline entity:
                var decoded = entity.Transcoded.ToString();
                if (decoded.Length > 0)
                    target.Spans.Add(SpanFor(decoded, style));
                break;
            case TaskList:
                break;
            case EmphasisInline emphasis:
                AppendChildren(target, emphasis, ApplyEmphasis(style, emphasis));
                break;
            case LinkInline { IsImage: true } image:
                AppendChildren(target, image, style with { Attributes = style.Attributes | FontAttributes.Italic });
                break;
            case LinkInline link:
                AppendLink(target, link.Url, link, style);
                break;
            case AutolinkInline autolink:
                var href = autolink.IsEmail ? "mailto:" + autolink.Url : autolink.Url;
                AppendLink(target, href, content: null, style, autolink.Url);
                break;
            case ContainerInline container:
                AppendChildren(target, container, style);
                break;
            default:
                var plain = PlainText(inline).Trim();
                if (plain.Length > 0)
                    target.Spans.Add(SpanFor(plain, style));
                break;
        }
    }

    private static void AppendLink(FormattedString target, string? url, ContainerInline? content, InlineStyle style, string? displayText = null)
    {
        var linkStyle = style with
        {
            Color = LinkColor,
            Decorations = style.Decorations | TextDecorations.Underline
        };
        var start = target.Spans.Count;
        if (content?.FirstChild is null)
        {
            var text = string.IsNullOrWhiteSpace(displayText) ? url : displayText;
            if (!string.IsNullOrWhiteSpace(text))
                target.Spans.Add(SpanFor(text, linkStyle));
        }
        else
        {
            AppendChildren(target, content, linkStyle);
        }

        if (!TryCreateLauncherUri(url, out var uri))
            return;

        for (var index = start; index < target.Spans.Count; index++)
        {
            target.Spans[index].GestureRecognizers.Add(new TapGestureRecognizer
            {
                Command = new Command(async () =>
                {
                    try { await Launcher.Default.OpenAsync(uri); }
                    catch { /* A failed link leaves the notes open. */ }
                })
            });
        }
    }

    private static bool TryCreateLauncherUri(string? url, out Uri uri)
    {
        if (!string.IsNullOrWhiteSpace(url) &&
            Uri.TryCreate(url, UriKind.Absolute, out uri!) &&
            uri.Scheme is "http" or "https" or "mailto")
            return true;

        uri = null!;
        return false;
    }

    private static InlineStyle ApplyEmphasis(InlineStyle style, EmphasisInline emphasis)
    {
        var attributes = style.Attributes;
        var decorations = style.Decorations;
        if (emphasis.DelimiterChar is '~')
            decorations |= TextDecorations.Strikethrough;
        else
        {
            if (emphasis.DelimiterCount >= 2)
                attributes |= FontAttributes.Bold;
            if (emphasis.DelimiterCount % 2 == 1)
                attributes |= FontAttributes.Italic;
        }

        return style with { Attributes = attributes, Decorations = decorations };
    }

    private static string PlainText(MarkdownObject? obj)
    {
        switch (obj)
        {
            case null:
                return "";
            case LiteralInline literal:
                return literal.Content.ToString();
            case CodeInline code:
                return code.Content ?? "";
            case HtmlEntityInline entity:
                return entity.Transcoded.ToString();
            case LineBreakInline:
                return "\n";
            case LeafBlock leaf when leaf.Inline is not null:
                return PlainText(leaf.Inline);
            case LeafBlock leaf:
                return leaf.Lines.ToString();
            case ContainerInline container:
                var inlineText = new System.Text.StringBuilder();
                for (var child = container.FirstChild; child is not null; child = child.NextSibling)
                    inlineText.Append(PlainText(child));
                return inlineText.ToString();
            case ContainerBlock blocks:
                var blockText = new System.Text.StringBuilder();
                foreach (var child in blocks)
                {
                    if (blockText.Length > 0)
                        blockText.AppendLine();
                    blockText.Append(PlainText(child));
                }
                return blockText.ToString();
            default:
                return "";
        }
    }

    private static InlineStyle BodyStyle() => new(FontAttributes.None, TextDecorations.None, TextSecondary, 14);

    private static InlineStyle HeadingStyle(int level) => new(
        FontAttributes.Bold,
        TextDecorations.None,
        TextPrimary,
        level switch { 1 => 20, 2 => 17, 3 => 15, _ => 14 });

    private static Span SpanFor(string text, InlineStyle style) => new()
    {
        Text = text,
        FontAttributes = style.Attributes,
        TextDecorations = style.Decorations,
        TextColor = style.Color,
        FontSize = style.FontSize
    };

    private static bool IsBlank(FormattedString text) =>
        text.Spans.Count == 0 || text.Spans.All(span => string.IsNullOrWhiteSpace(span.Text));

    private static Label PlainLabel(string text) => new()
    {
        Text = text,
        TextColor = TextSecondary,
        FontSize = 14,
        LineBreakMode = LineBreakMode.WordWrap
    };

    private static Label EmptyLabel() => PlainLabel("Keine Änderungshinweise vorhanden.");

    private static string? MonospaceFont()
    {
        var platform = DeviceInfo.Platform;
        if (platform == DevicePlatform.WinUI)
            return "Consolas";
        if (platform == DevicePlatform.Android)
            return "monospace";
        if (platform == DevicePlatform.iOS || platform == DevicePlatform.MacCatalyst)
            return "Menlo";
        return null;
    }
}

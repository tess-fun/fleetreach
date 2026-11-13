using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.Formats.Jpeg;
static class Program
{
    static void Main()
    {
        using var img = new Image<Rgba32>(64, 48);
        img.Mutate(x => x.BackgroundColor(Color.CornflowerBlue).Resize(32, 24).Grayscale().Rotate(90).GaussianBlur(1.2f));
        using var png = new MemoryStream();
        img.Save(png, new PngEncoder());
        using var jpg = new MemoryStream();
        img.SaveAsJpeg(jpg, new JpegEncoder { Quality = 80 });
        png.Position = 0; jpg.Position = 0;
        using var a = Image.Load(png);
        using var b = Image.Load<Rgb24>(jpg);
        var fmt = Image.DetectFormat(png.ToArray());
        Console.WriteLine($"{a.Width}x{a.Height} {b.Width} {fmt?.Name} {img[0, 0]}");
        using var gif = new MemoryStream(); a.SaveAsGif(gif); gif.Position = 0; using var g = Image.Load(gif);
        using var bmp = new MemoryStream(); a.SaveAsBmp(bmp);
        Console.WriteLine(g.Frames.Count);
    }
}

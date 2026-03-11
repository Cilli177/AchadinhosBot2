var assembly = System.Reflection.Assembly.LoadFrom(@"c:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\bin\Debug\net8.0\AchadinhosBot.Next.dll");
var programType = assembly.GetType("Program");
if (programType == null) programType = assembly.GetType("AchadinhosBot.Next.Program");

var method = programType.GetMethod("BuildCatalogPageHtml", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

var itemType = assembly.GetType("AchadinhosBot.Next.Domain.Models.CatalogOfferItem");
var itemsListType = typeof(System.Collections.Generic.List<>).MakeGenericType(itemType);
var items = System.Activator.CreateInstance(itemsListType);

var item1 = System.Activator.CreateInstance(itemType);
itemType.GetProperty("ItemNumber").SetValue(item1, 1);
itemType.GetProperty("ProductName").SetValue(item1, "Smartphone Apple iPhone 15 Pro Max (256 GB) - Titânio Natural");
itemType.GetProperty("PriceText").SetValue(item1, "R$ 7.000,00");
itemType.GetProperty("ImageUrl").SetValue(item1, "https://example.com/img.jpg");
itemType.GetProperty("Store").SetValue(item1, "Amazon");
itemType.GetProperty("PublishedAt").SetValue(item1, System.DateTimeOffset.UtcNow);

var addMethod = itemsListType.GetMethod("Add");
addMethod.Invoke(items, new object[] { item1 });

try {
    var html = (string)method.Invoke(null, new object[] { items, "", "https://achadinhos.tv.br/catalogo" });
    System.IO.File.WriteAllText(@"C:\Users\overl\.gemini\antigravity\brain\00daeec3-5cbb-4f29-b74f-b5a8e5c459a7\vip_catalog_index_preview.html", html);
    System.Console.WriteLine("Success");
} catch(System.Exception ex) {
    System.Console.WriteLine(ex.ToString());
}

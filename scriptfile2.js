// Minimal JScript file writer (scriptfile2.js)
// Compile C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe scriptfile2.js
// For testing arb code ex to write to C:\Users\Public\\Downloads\
var fso = new ActiveXObject("Scripting.FileSystemObject");
var d = new Date();
var n = Math.random();
var filename = "C:\\Users\\Public\\Downloads\\file" + d.getTime() + ".txt";
var file = fso.CreateTextFile(filename, true);
file.WriteLine('Hello, today is ' + d + ' and this is random - ' + n);
file.Close();

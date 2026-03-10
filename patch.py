import codecs
import re

program_path = r'c:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\Program.cs'
tmp_csharp = codecs.open(r'c:\AchadinhoBot2\AchadinhosBot2\tmp_csharp.txt', 'r', 'utf-8').read()
program = codecs.open(program_path, 'r', 'utf-8').read()

pattern = re.compile(r'static string BuildCatalogItemPageHtml\([^)]+\)\s*\{.*?return sb\.ToString\(\);\s*\}', re.DOTALL)

if not pattern.search(program):
    print("Method not found!")
else:
    new_program = pattern.sub(tmp_csharp, program)
    codecs.open(program_path, 'w', 'utf-8').write(new_program)
    print("Patched successfully!")

import sys

try:
    with open(r'C:\AchadinhoBot2\AchadinhosBot2\AchadinhosBot.Next\wwwroot\debug_social.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    id_to_find = 'MLB61417067'
    index = content.find(id_to_find)
    
    if index != -1:
        start = max(0, index - 200)
        end = min(len(content), index + 2000)
        print(content[start:end])
    else:
        print("ID not found")
except Exception as e:
    print(f"Error: {e}")

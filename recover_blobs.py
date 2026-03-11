import os
import subprocess

obj_dir = r".git\lost-found\other"
if not os.path.exists(obj_dir):
    print("No lost-found other directory")
    exit(0)

targets = [
    "BotConversorWebhookConsumer",
    "ProcessBotConversorWebhookCommand",
    "ITelegramTransport",
    "IWhatsAppTransport",
    "TelegramSendResult"
]

for filename in os.listdir(obj_dir):
    filepath = os.path.join(obj_dir, filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for t in targets:
                if t in content:
                    print(f"Found {t} in {filename}")
                    # Save it back as a recovered file
                    with open(f"recovered_{t}_{filename}.cs", 'w', encoding='utf-8') as out:
                        out.write(content)
                    break
    except:
        pass

print("Recovery search complete.")

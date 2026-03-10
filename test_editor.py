from playwright.sync_api import sync_playwright
import time
import os

def test_editor():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        
        # Open page
        page.goto("http://localhost:8081/conversor-admin.html")
        time.sleep(1)
        
        # Inject auth key to session storage to bypass login
        page.evaluate("sessionStorage.setItem('vip_admin_key', 'dev-local-key');")
        page.goto("http://localhost:8081/conversor-admin.html")
        time.sleep(1)

        # Input URL 
        page.fill("#urlInput", "https://www.amazon.com.br/Echo-Pop-Preto-Alexa/dp/B0BXZ4ZBBK/")
        page.click("#submitBtn")
        
        # Wait for preview to load
        time.sleep(5)
        
        # Switch to Visual Tab
        page.evaluate("switchTab('visual')")
        time.sleep(1)

        print("Checking for Editar button...")
        
        # Open Editor Modal by calling the function directly to bypass tricky SVG clicks
        page.evaluate("openEditorModal()")
        time.sleep(2)
        
        # Add Text and Badges inside the Modal
        page.fill("#editorTextInput", "SUPER DESCONTO")
        page.evaluate("addEditorText()")
        time.sleep(0.5)
        
        page.evaluate("addEditorBadge('discount')")
        page.evaluate("addEditorBadge('frete')")
        time.sleep(1)
        
        # Screenshot the Modal State
        screenshot_path = os.path.abspath("modal_screenshot.png")
        page.screenshot(path=screenshot_path)
        print(f"Saved modal screenshot to {screenshot_path}")

        # Apply changes
        page.evaluate("applyEditorChanges()")
        time.sleep(2)

        # Final screenshot of the mockup
        final_path = os.path.abspath("final_mockup.png")
        page.screenshot(path=final_path)
        print(f"Saved final mockup to {final_path}")

        browser.close()

if __name__ == "__main__":
    test_editor()

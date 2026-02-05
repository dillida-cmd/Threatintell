#!/usr/bin/env python3
"""
URL Screenshot Service for ShieldTier
Captures screenshots of URLs using headless browsers in isolated environment
"""

import os
import sys
import json
import base64
import tempfile
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, Optional, Tuple
import shutil

# Configuration
SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), 'screenshots')
SCREENSHOT_TIMEOUT = 30  # seconds
MAX_SCREENSHOT_WIDTH = 1920
MAX_SCREENSHOT_HEIGHT = 1080
USER_AGENTS = {
    'chrome_windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'chrome_mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'firefox_windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'firefox_linux': 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
}

# Ensure screenshot directory exists
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def check_browser_available() -> Dict[str, bool]:
    """Check which browsers/tools are available"""
    available = {
        'chromium': False,
        'firefox': False,
        'puppeteer': False,
        'playwright': False,
        'cutycapt': False,
        'wkhtmltoimage': False,
    }

    # Check Chromium (prioritize google-chrome over snap versions which have permission issues)
    for cmd in ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser',
                '/snap/bin/chromium', '/usr/bin/chromium', '/usr/bin/chromium-browser']:
        if shutil.which(cmd) or (cmd.startswith('/') and os.path.exists(cmd)):
            available['chromium'] = True
            break

    # Check Firefox
    if shutil.which('firefox'):
        available['firefox'] = True

    # Check CutyCapt (Qt-based screenshot tool)
    if shutil.which('cutycapt'):
        available['cutycapt'] = True

    # Check wkhtmltoimage
    if shutil.which('wkhtmltoimage'):
        available['wkhtmltoimage'] = True

    # Check Node.js tools
    try:
        result = subprocess.run(['npx', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            available['puppeteer'] = True
            available['playwright'] = True
    except:
        pass

    return available


def capture_with_chromium(url: str, output_path: str, user_agent: str = None,
                          width: int = 1920, height: int = 1080, timeout: int = 30) -> Tuple[bool, str]:
    """Capture screenshot using headless Chromium"""

    # Find Chromium binary (prioritize google-chrome over snap versions which have permission issues)
    chromium_bin = None
    for cmd in ['google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser',
                '/snap/bin/chromium', '/usr/bin/chromium', '/usr/bin/chromium-browser']:
        if shutil.which(cmd) or (cmd.startswith('/') and os.path.exists(cmd)):
            chromium_bin = cmd
            break

    if not chromium_bin:
        return False, "Chromium not found"

    user_agent = user_agent or USER_AGENTS['chrome_windows']

    args = [
        chromium_bin,
        '--headless',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        f'--window-size={width},{height}',
        f'--user-agent={user_agent}',
        '--hide-scrollbars',
        '--screenshot=' + output_path,
        url
    ]

    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True, "Screenshot captured successfully"
        else:
            return False, f"Screenshot failed: {result.stderr.decode()[:200]}"
    except subprocess.TimeoutExpired:
        return False, "Screenshot timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"


def capture_with_firefox(url: str, output_path: str, user_agent: str = None,
                         width: int = 1920, height: int = 1080, timeout: int = 30) -> Tuple[bool, str]:
    """Capture screenshot using headless Firefox"""

    if not shutil.which('firefox'):
        return False, "Firefox not found"

    # Create temporary profile directory to avoid conflicts with running Firefox
    profile_dir = tempfile.mkdtemp(prefix='firefox_screenshot_')

    try:
        # Firefox headless screenshot with temporary profile
        args = [
            'firefox',
            '--headless',
            '--no-remote',
            '-profile', profile_dir,
            f'--window-size={width},{height}',
            f'--screenshot={output_path}',
            url
        ]

        result = subprocess.run(args, capture_output=True, timeout=timeout)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True, "Screenshot captured with Firefox"
        else:
            stderr = result.stderr.decode()[:200] if result.stderr else "Unknown error"
            return False, f"Firefox screenshot failed: {stderr}"
    except subprocess.TimeoutExpired:
        return False, "Firefox timed out"
    except Exception as e:
        return False, f"Firefox error: {str(e)}"
    finally:
        # Clean up temporary profile
        try:
            shutil.rmtree(profile_dir)
        except:
            pass


def capture_with_puppeteer(url: str, output_path: str, user_agent: str = None,
                           width: int = 1920, height: int = 1080, timeout: int = 30) -> Tuple[bool, str]:
    """Capture screenshot using Puppeteer (Node.js)"""

    user_agent = user_agent or USER_AGENTS['chrome_windows']

    # Create temporary Node.js script
    script = f'''
const puppeteer = require('puppeteer');

(async () => {{
    const browser = await puppeteer.launch({{
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-web-security'
        ]
    }});

    const page = await browser.newPage();
    await page.setViewport({{ width: {width}, height: {height} }});
    await page.setUserAgent('{user_agent}');

    try {{
        await page.goto('{url}', {{
            waitUntil: 'networkidle2',
            timeout: {timeout * 1000}
        }});
        await page.screenshot({{ path: '{output_path}', fullPage: false }});
        console.log('SUCCESS');
    }} catch (e) {{
        console.log('ERROR: ' + e.message);
    }}

    await browser.close();
}})();
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        result = subprocess.run(
            ['npx', 'puppeteer', 'screenshot', '--url', url, '--output', output_path],
            capture_output=True,
            timeout=timeout + 10
        )

        # Fallback to running the script directly
        if not os.path.exists(output_path):
            result = subprocess.run(
                ['node', script_path],
                capture_output=True,
                timeout=timeout + 10
            )

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True, "Screenshot captured with Puppeteer"
        else:
            return False, f"Puppeteer failed: {result.stderr.decode()[:200]}"

    except subprocess.TimeoutExpired:
        return False, "Puppeteer timed out"
    except Exception as e:
        return False, f"Puppeteer error: {str(e)}"
    finally:
        os.unlink(script_path)


def capture_with_playwright(url: str, output_path: str, browser_type: str = 'chromium',
                            user_agent: str = None, width: int = 1920, height: int = 1080,
                            timeout: int = 30) -> Tuple[bool, str]:
    """Capture screenshot using Playwright"""

    user_agent = user_agent or USER_AGENTS['chrome_windows']

    script = f'''
const {{ {browser_type} }} = require('playwright');

(async () => {{
    const browser = await {browser_type}.launch({{ headless: true }});
    const context = await browser.newContext({{
        viewport: {{ width: {width}, height: {height} }},
        userAgent: '{user_agent}'
    }});
    const page = await context.newPage();

    try {{
        await page.goto('{url}', {{ timeout: {timeout * 1000}, waitUntil: 'networkidle' }});
        await page.screenshot({{ path: '{output_path}' }});
        console.log('SUCCESS');
    }} catch (e) {{
        console.log('ERROR: ' + e.message);
    }}

    await browser.close();
}})();
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        result = subprocess.run(
            ['node', script_path],
            capture_output=True,
            timeout=timeout + 10
        )

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True, f"Screenshot captured with Playwright ({browser_type})"
        else:
            return False, f"Playwright failed: {result.stderr.decode()[:200]}"

    except subprocess.TimeoutExpired:
        return False, "Playwright timed out"
    except Exception as e:
        return False, f"Playwright error: {str(e)}"
    finally:
        os.unlink(script_path)


def capture_with_wkhtmltoimage(url: str, output_path: str, width: int = 1920,
                                height: int = 1080, timeout: int = 30) -> Tuple[bool, str]:
    """Capture screenshot using wkhtmltoimage"""

    if not shutil.which('wkhtmltoimage'):
        return False, "wkhtmltoimage not found"

    args = [
        'wkhtmltoimage',
        '--format', 'png',
        '--width', str(width),
        '--height', str(height),
        '--javascript-delay', '3000',
        '--load-error-handling', 'ignore',
        '--load-media-error-handling', 'ignore',
        url,
        output_path
    ]

    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True, "Screenshot captured with wkhtmltoimage"
        else:
            return False, f"wkhtmltoimage failed: {result.stderr.decode()[:200]}"
    except subprocess.TimeoutExpired:
        return False, "wkhtmltoimage timed out"
    except Exception as e:
        return False, f"wkhtmltoimage error: {str(e)}"


def capture_url_screenshot(url: str, user_agent: str = None, browser: str = 'auto',
                           width: int = 1920, height: int = 1080,
                           timeout: int = 30) -> Dict:
    """
    Main function to capture URL screenshot

    Args:
        url: URL to capture
        user_agent: Custom user agent string or key from USER_AGENTS
        browser: 'chromium', 'firefox', 'puppeteer', 'playwright', 'wkhtmltoimage', or 'auto'
        width: Screenshot width
        height: Screenshot height
        timeout: Timeout in seconds

    Returns:
        Dict with screenshot data and metadata
    """

    result = {
        'success': False,
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'browser': None,
        'user_agent': None,
        'screenshot_base64': None,
        'screenshot_path': None,
        'width': width,
        'height': height,
        'error': None,
        'file_size': 0,
    }

    # Resolve user agent
    if user_agent and user_agent in USER_AGENTS:
        user_agent = USER_AGENTS[user_agent]

    result['user_agent'] = user_agent

    # Generate unique filename
    url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"screenshot_{url_hash}_{timestamp}.png"
    output_path = os.path.join(SCREENSHOT_DIR, filename)

    # Check available tools
    available = check_browser_available()

    # Determine which tool to use
    capture_methods = []

    if browser == 'auto':
        # Try in order of preference
        if available['chromium']:
            capture_methods.append(('chromium', capture_with_chromium))
        if available['firefox']:
            capture_methods.append(('firefox', capture_with_firefox))
        if available['puppeteer']:
            capture_methods.append(('puppeteer', capture_with_puppeteer))
        if available['playwright']:
            capture_methods.append(('playwright', lambda u, o, **kw: capture_with_playwright(u, o, 'chromium', **kw)))
        if available['wkhtmltoimage']:
            capture_methods.append(('wkhtmltoimage', capture_with_wkhtmltoimage))
    elif browser == 'chromium' and available['chromium']:
        capture_methods.append(('chromium', capture_with_chromium))
    elif browser == 'puppeteer' and available['puppeteer']:
        capture_methods.append(('puppeteer', capture_with_puppeteer))
    elif browser == 'playwright' and available['playwright']:
        capture_methods.append(('playwright', lambda u, o, **kw: capture_with_playwright(u, o, 'chromium', **kw)))
    elif browser == 'firefox' and available['firefox']:
        capture_methods.append(('firefox', capture_with_firefox))
    elif browser == 'wkhtmltoimage' and available['wkhtmltoimage']:
        capture_methods.append(('wkhtmltoimage', capture_with_wkhtmltoimage))

    if not capture_methods:
        result['error'] = (
            "No screenshot tools available. Install one of: "
            "Chromium (apt install chromium), "
            "Puppeteer (npm install -g puppeteer), "
            "Playwright (npm install -g playwright), or "
            "wkhtmltoimage (apt install wkhtmltopdf). "
            f"Current availability: {available}"
        )
        return result

    # Try each method until one succeeds
    for browser_name, capture_func in capture_methods:
        try:
            if browser_name == 'wkhtmltoimage':
                success, message = capture_func(url, output_path, width=width, height=height, timeout=timeout)
            else:
                success, message = capture_func(url, output_path, user_agent=user_agent,
                                               width=width, height=height, timeout=timeout)

            if success and os.path.exists(output_path):
                result['success'] = True
                result['browser'] = browser_name
                result['screenshot_path'] = output_path
                result['file_size'] = os.path.getsize(output_path)

                # Read and encode as base64
                with open(output_path, 'rb') as f:
                    result['screenshot_base64'] = base64.b64encode(f.read()).decode('utf-8')

                return result
            else:
                result['error'] = message

        except Exception as e:
            result['error'] = f"{browser_name} error: {str(e)}"
            continue

    return result


def get_service_status() -> Dict:
    """Get screenshot service status"""
    available = check_browser_available()

    return {
        'service': 'screenshot',
        'status': 'available' if any(available.values()) else 'unavailable',
        'tools': available,
        'screenshot_dir': SCREENSHOT_DIR,
        'timeout': SCREENSHOT_TIMEOUT,
        'supported_browsers': list(USER_AGENTS.keys()),
    }


# CLI interface for testing
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python screenshot_service.py <url> [browser] [user_agent]")
        print("\nService Status:")
        print(json.dumps(get_service_status(), indent=2))
        sys.exit(1)

    url = sys.argv[1]
    browser = sys.argv[2] if len(sys.argv) > 2 else 'auto'
    user_agent = sys.argv[3] if len(sys.argv) > 3 else None

    print(f"Capturing screenshot of: {url}")
    result = capture_url_screenshot(url, user_agent=user_agent, browser=browser)

    # Don't print base64 to console
    output = {k: v for k, v in result.items() if k != 'screenshot_base64'}
    output['has_screenshot'] = result['screenshot_base64'] is not None
    print(json.dumps(output, indent=2))

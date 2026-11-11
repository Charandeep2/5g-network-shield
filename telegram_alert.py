import os
import sys
import time
import requests
from dotenv import load_dotenv, set_key

# Load existing environment variables
load_dotenv()

# ============================================================================
# 📱 FRI-DAY 5G SOC: TELEGRAM MOBILE COMMAND ALERTS MODULE
# ============================================================================
#
# QUICK SETUP:
# ----------------------------------------------------------------------------
# 1. BOT TOKEN:
#    From @BotFather. Format is: <bot_id>:<secret_hash>
#    e.g. "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ"
#
# 2. CHAT ID:
#    From @userinfobot (send /start to @userinfobot on Telegram to see your numeric "Id").
#    OR simply open your new bot in Telegram and click START / send any message!
#    Our auto-detect engine will automatically discover your Chat ID from getUpdates.
# ----------------------------------------------------------------------------
# ============================================================================

# Read from .env if present
DEFAULT_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DEFAULT_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", DEFAULT_BOT_TOKEN).strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", DEFAULT_CHAT_ID).strip()

_cached_auto_chat_id = ""


def get_token() -> str:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip() or TELEGRAM_BOT_TOKEN or DEFAULT_BOT_TOKEN
    return token.strip()


def auto_detect_chat_id(token: str) -> str:
    """Queries Telegram getUpdates to auto-detect the user's Chat ID if they clicked Start or messaged the bot."""
    global _cached_auto_chat_id
    if _cached_auto_chat_id:
        return _cached_auto_chat_id

    if not token or ":" not in token:
        return ""

    try:
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        res = requests.get(url, timeout=3.0)
        if res.ok:
            data = res.json()
            results = data.get("result", [])
            for item in reversed(results):
                msg = item.get("message") or item.get("my_chat_member")
                if msg:
                    chat = msg.get("chat", {})
                    found_id = str(chat.get("id", ""))
                    if found_id:
                        _cached_auto_chat_id = found_id
                        print(f"✨ [Telegram Auto-Detect] Found Chat ID {found_id} from your Telegram message!")
                        return found_id
    except Exception:
        pass
    return ""


def get_chat_id() -> str:
    global _cached_auto_chat_id
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip() or TELEGRAM_CHAT_ID or DEFAULT_CHAT_ID
    if not chat_id:
        token = get_token()
        detected = auto_detect_chat_id(token)
        if detected:
            chat_id = detected
            _cached_auto_chat_id = detected
    return chat_id.strip()


def is_configured() -> bool:
    token = get_token()
    chat_id = get_chat_id()
    return bool(token and ":" in token and chat_id)


def send_telegram_alert(attacker_ip: str, teid_display: str, mse: float, extra_info: str = "") -> bool:
    """
    Dispatches a high-priority DEFCON-1 alert to your phone via Telegram Bot API.
    Called automatically by app.py whenever a zero-day breach is detected.
    """
    token = get_token()
    chat_id = get_chat_id()

    if not is_configured():
        print(f"📱 [Mobile Alert Standby] Alert triggered for {attacker_ip}. (To receive on phone, open your bot in Telegram and click START, or add your Chat ID from @userinfobot)")
        return False

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    message = (
        f"🚨 *FRI-DAY 5G SOC BREACH ALERT*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ *SEV-1 CRITICAL ZERO-DAY BREACH*\n"
        f"🎯 *Target:* 3GPP UPF N3 (UDP:2152)\n"
        f"📡 *Attacker IP:* `{attacker_ip}`\n"
        f"💥 *Exploit Weapon:* `TEID {teid_display}`\n"
        f"📊 *Neural MSE:* `{mse:.2f}` (Threshold: 0.0800)\n"
        f"🛡️ *DPI Defense:* `0xFFFFFFFF Signature Blocked`\n"
        f"⚡ *Auto-Kill Switch:* `Windows Kernel Drop Enforced`\n"
        f"🕒 *Timestamp:* `{now_str}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ *Autonomous Edge Mitigation Deployed*"
    )

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        resp = requests.post(url, json=payload, timeout=4.0)
        if resp.status_code == 200:
            print(f"📱 [Mobile Alert] PUSH SUCCESS! Sent DEFCON-1 alert to Telegram Chat ID {chat_id}")
            return True
        else:
            print(f"⚠️ [Mobile Alert] Telegram returned HTTP {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"⚠️ [Mobile Alert] Failed to dispatch Telegram alert: {e}")
        return False


def test_telegram_connection() -> bool:
    """Sends a verification ping to your phone."""
    token = get_token()
    chat_id = get_chat_id()

    if not is_configured():
        print("\n❌ Telegram credentials incomplete:")
        print(f"   Bot Token: {token[:12]}... (Valid: {bool(':' in token)})")
        print(f"   Chat ID:   {chat_id or '(Missing - Open your bot in Telegram and send /start, or message @userinfobot)'}")
        print("\n💡 TIP: Open your bot in Telegram and click 'START' or send any message to it!")
        print("Then run this test again — it will auto-detect your Chat ID!\n")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    test_message = (
        f"🔔 *FRI-DAY 5G SOC: Mobile Link Verified!*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ Successfully linked Dell G15 Defense Daemon.\n"
        f"📡 Real-time 5G threat alerts will buzz your phone instantly during the demo!\n"
        f"🕒 Time: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Active Defense: L7 DPI Filter + Windows Host Killswitch."
    )

    print(f"\n[*] Sending test ping to Telegram (Chat ID: {chat_id})...")
    try:
        resp = requests.post(url, json={"chat_id": chat_id, "text": test_message, "parse_mode": "Markdown"}, timeout=5.0)
        if resp.status_code == 200:
            print("✅ SUCCESS! Test ping delivered to your phone! Check your Telegram app right now.\n")
            return True
        else:
            print(f"❌ Telegram API Error ({resp.status_code}): {resp.text}\n")
            return False
    except Exception as e:
        print(f"❌ Connection Error: {e}\n")
        return False


# ============================================================================
# INTERACTIVE CLI SETUP & TEST RUNNER
# Run: python telegram_alert.py
# ============================================================================
if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("📱 FRI-DAY 5G SOC: TELEGRAM MOBILE ALERTS CONFIGURATOR")
    print("=" * 65)

    curr_token = get_token()
    curr_chat = get_chat_id()

    print(f"Bot Token: {curr_token[:10]}...{curr_token[-6:] if len(curr_token) > 15 else '(Not Set)'}")
    print(f"Chat ID:   {curr_chat if curr_chat else '(Not Set - send message to your bot to auto-detect)'}")
    print("=" * 65)

    print("\nSelect an option:")
    print("  [1] Send a Test Ping to Phone Right Now")
    print("  [2] Auto-Detect Chat ID (after sending /start to your bot)")
    print("  [3] Manually Enter / Update Chat ID")
    print("  [4] Simulate a Full DEFCON-1 Breach Alert on Phone")
    print("  [5] Exit")

    choice = input("\nEnter choice (1-5) [Default: 1]: ").strip() or "1"

    if choice == "2":
        print("\n[*] Checking Telegram getUpdates for incoming messages...")
        cid = auto_detect_chat_id(curr_token)
        if cid:
            print(f"✅ Discovered your Chat ID: {cid}!")
            try:
                set_key(".env", "TELEGRAM_CHAT_ID", cid)
                os.environ["TELEGRAM_CHAT_ID"] = cid
                print("Saved Chat ID to .env!")
            except Exception:
                pass
            test_telegram_connection()
        else:
            print("⚠️ No messages found from you yet.")
            print("Please open your bot in Telegram and send '/start' or 'hello', then try again!")

    elif choice == "3":
        new_chat = input("\nEnter your numeric Chat ID from @userinfobot: ").strip()
        if new_chat:
            try:
                set_key(".env", "TELEGRAM_BOT_TOKEN", curr_token)
                set_key(".env", "TELEGRAM_CHAT_ID", new_chat)
                os.environ["TELEGRAM_CHAT_ID"] = new_chat
                print(f"✅ Saved Chat ID {new_chat} to .env!")
            except Exception:
                pass
            test_telegram_connection()

    elif choice == "4":
        print("\n[*] Simulating real-time SEV-1 attack alert...")
        send_telegram_alert(
            attacker_ip="192.168.43.202",
            teid_display="0xFFFFFFFF",
            mse=106812.51
        )

    elif choice == "1":
        test_telegram_connection()

    else:
        print("Exiting.")

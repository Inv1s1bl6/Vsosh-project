from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import requests
from urllib.parse import urlparse
import tldextract
import re


TOKEN = "8356305327:AAGtZ1Rt6Z8_CJREhOIWv9tWcuQCFmzUY2o"
GOOGLE_KEY = "AIzaSyAhQ08V1669ZcNLIhKWnQcbTPzxkYRYiFs"


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Скинь ссылку -- попробую проверить, нет ли там фишинга.\n"
        "Работает не идеально, но базовые вещи ловит."
    )


def chekc_Google_balck_list(url):
    api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}"

    body = {
        "client": {"clientId": "phish-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(api, json=body, timeout=5)
    except Exception as e:
        return {"status": None, "text": f"Google SB не ответил: {e}", "items": []}
    if r.status_code != 200:
        return {"status": None, "text": f"Статус {r.status_code}", "items": []}
    data = r.json()
    if data.get("matches"):
        return {
            "status": False,
            "text": "Google кое-что нашёл",
            "items": [i.get("threatType") for i in data["matches"]]
        }
    return {"status": True, "text": "Пусто", "items": []}


def heuristic_analysis(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    ext = tldextract.extract(url)
    res = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        res.append("Домен -- это IP. Обычно это настораживает.")
    if host.count(".") > 3:
        res.append("Много поддоменов. Часто так делают мошенники.")
    s = ".".join(filter(None, [ext.subdomain, ext.domain, ext.suffix])).lower()
    for w in ["login", "verify", "secure", "bank"]:
        if w in s:
            res.append(f"В домене есть слово «{w}» -- выглядит подозрительно.")
    if ext.domain and re.search(r"[аеорсху]", ext.domain.lower()):
        res.append("Есть символы, похожие на кириллицу.")
    for b in ["google", "vk", "apple"]:
        if b in s and ext.domain.lower() != b:
            res.append(f"Может выдавать себя за «{b}».")
    return res


def check_redirects(url):
    parsed = urlparse(url)
    q = parsed.query.lower()
    res = []
    for key in ["url", "next", "redirect", "to"]:
        if key in q:
            res.append(f"Похоже на редирект через «{key}».")
    if "http" in q:
        res.append("В параметрах есть ссылка. Могут быть перехрды.")
    return res


def check_availability(url):
    out = []
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        out.append(f"HTTP: {r.status_code}")
    except Exception:
        out.append("Сайт не откликнулся.")
    if url.startswith("https://"):
        out.append("HTTPS -- да")
    else:
        out.append("HTTPS -- нет")
    return out


async def check_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    txt = [f"Проверяю: {url}", ""]
    sb = chekc_Google_balck_list(url)
    txt.append(f"Google SB: {sb['text']}")
    for i in sb["items"]:
        txt.append(f"- {i}")
    txt.append("")
    heur = heuristic_analysis(url)
    red = check_redirects(url)
    flags = heur + red
    if flags:
        txt.append("Нашёл кое-что подозрительное:")
        for f in flags:
            txt.append(f"- {f}")
    else:
        txt.append("На глаз -- выглядит нормально.")
    txt.append("")
    txt.append("Доступность сайта:")
    for v in check_availability(url):
        txt.append(f"- {v}")
    txt.append("")
    txt.append(f"Всего предупреждений: {len(flags)}")
    return "\n".join(txt)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if "." in text or "http" in text:
        msg = await update.message.reply_text("Щас гляну...")
        rep = await check_url(text)
        await msg.edit_text(rep)
    else:
        await update.message.reply_text("Отправь ссылочку")


if __name__ == "__main__":
    print("w")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()
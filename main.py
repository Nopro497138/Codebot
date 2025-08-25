# This is the whole code for the bot. You can copy it but you NEED to ask us first.
# If you do it without permission then we have to take action.













import os
import re
import json
import sqlite3
import textwrap
import aiohttp
import asyncio
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import discord
from discord import app_commands
from discord.ext import commands

# ---------- CONFIG ----------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
PISTON_URL = os.getenv("PISTON_URL", "http://localhost:2000")  # z.B. http://localhost:2000
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # optional, für KI-Reviews (Platzhalter)
DB_PATH = os.getenv("DB_PATH", "submissions.db")
MAX_CODE_LENGTH = 8000  # fallback limit for code field
# ----------------------------

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- DB helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS guild_config(
        guild_id INTEGER PRIMARY KEY,
        form_channel_id INTEGER
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS submissions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER,
        user_id INTEGER,
        language TEXT,
        code TEXT,
        status TEXT,
        ai_summary TEXT,
        run_stdout TEXT,
        run_stderr TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS votes(
        submission_id INTEGER,
        user_id INTEGER,
        vote INTEGER,
        PRIMARY KEY (submission_id, user_id)
      )
    """)
    conn.commit()
    conn.close()

def set_form_channel(guild_id: int, channel_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO guild_config(guild_id, form_channel_id) VALUES (?, ?)", (guild_id, channel_id))
    conn.commit()
    conn.close()

def get_form_channel(guild_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT form_channel_id FROM guild_config WHERE guild_id = ?", (guild_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def save_submission(guild_id, user_id, language, code, status="pending", ai_summary=None, stdout=None, stderr=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO submissions(guild_id,user_id,language,code,status,ai_summary,run_stdout,run_stderr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (guild_id, user_id, language, code, status, ai_summary, stdout, stderr))
    sub_id = cur.lastrowid
    conn.commit()
    conn.close()
    return sub_id

def update_submission_result(submission_id, status=None, ai_summary=None, stdout=None, stderr=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    sets = []
    vals = []
    if status is not None:
        sets.append("status = ?"); vals.append(status)
    if ai_summary is not None:
        sets.append("ai_summary = ?"); vals.append(ai_summary)
    if stdout is not None:
        sets.append("run_stdout = ?"); vals.append(stdout)
    if stderr is not None:
        sets.append("run_stderr = ?"); vals.append(stderr)
    vals.append(submission_id)
    cur.execute(f"UPDATE submissions SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    conn.close()

def set_vote(submission_id, user_id, vote):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO votes(submission_id,user_id,vote) VALUES (?, ?, ?)", (submission_id, user_id, vote))
    conn.commit()
    conn.close()

def get_votes(submission_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT SUM(vote) as score, COUNT(*) as total FROM votes WHERE submission_id = ?", (submission_id,))
    row = cur.fetchone()
    conn.close()
    return {"score": row[0] or 0, "count": row[1] or 0}

# ---------- Basic static "malware" heuristics ----------
SUSPICIOUS_PATTERNS = [
    r"\beval\(", r"\bexec\(", r"import\s+os", r"subprocess\.", r"socket\.", r"requests\.", r"ftplib\.",
    r"open\([^)]*['\"]/etc", r"rm\s+-rf", r"os\.remove", r"shutil\.rmtree", r"popen\(", r"base64\.b64decode",
    r"urllib\.request", r"paramiko", r"ctypes\.", r"System\.Diagnostics", r"Process\.Start", r"CreateRemoteThread"
]

def static_risk_check(code: str):
    """Very simple heuristic scanner. Returns (risk_level:int 0-100, reasons:list)."""
    reasons = []
    lowered = code.lower()
    score = 0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, code):
            reasons.append(f"Matched suspicious pattern `{pat}`")
            score += 30
    # length/obfuscation heuristics
    if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", code):  # base64 blob heuristic
        reasons.append("Detected long base64-like blob (possible obfuscation).")
        score += 20
    # Network/file IO
    if re.search(r"\b(open|os\.open|Path\()", code) and re.search(r"read|write|w\+|rb", lowered):
        reasons.append("Contains file read/write patterns.")
        score += 10
    score = min(100, score)
    return score, reasons

# ---------- AI review placeholders ----------
async def ai_review_code(code: str, language: str) -> dict:
    """
    Platzhalter für KI-Review: Wenn OPENAI_API_KEY gesetzt ist, kannst du hier
    einen echten OpenAI-Aufruf implementieren. Rückgabewert sollte ein dict sein:
      { "risk_score": int(0-100), "summary": str }
    Aktuell: kombinieren statische heuristics + simple summary.
    """
    risk_score, reasons = static_risk_check(code)
    # lightweight "summary"
    summary = "Automatische Zusammenfassung:\n"
    first_lines = "\n".join(code.splitlines()[:10])
    summary += f"Erste Zeilen:\n```\n{first_lines}\n```\n"
    if reasons:
        summary += "Potentielle Risiken:\n- " + "\n- ".join(reasons)
    else:
        summary += "Keine offensichtlichen statischen Risk-Marker gefunden."
    return {"risk_score": risk_score, "summary": summary}

# ---------- Piston execution ----------
# NOTE: You must run your own piston instance or set PISTON_URL to a trusted one.
# Docs: https://piston.readthedocs.io/en/latest/api-v2/
async def run_code_in_piston(session: aiohttp.ClientSession, language: str, code: str, timeout_ms: int = 3000):
    url = PISTON_URL.rstrip("/") + "/api/v2/execute"
    payload = {
        "language": language,
        "files": [
            {"name": f"submission.{language}", "content": code}
        ],
        "stdin": "",
        "args": [],
        "run_timeout": timeout_ms
    }
    async with session.post(url, json=payload, timeout=10) as resp:
        if resp.status != 200:
            text = await resp.text()
            return {"error": f"Piston returned status {resp.status}: {text}"}
        return await resp.json()

# ---------- Create highlight "screenshot" (image) ----------
def render_code_highlight_image(code: str, highlight_lines=(0,5)):
    """
    Erzeugt ein PNG mit einer Code-Auswahl. highlight_lines ist ein tuple (start,end)
    """
    lines = code.splitlines()
    start, end = highlight_lines
    selected = lines[start:end]
    if not selected:
        selected = lines[:min(10, len(lines))]

    text = "\n".join(selected)
    # simple image render
    font_size = 16
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()
    margin = 12
    # calculate size
    max_w = max([font.getsize(l)[0] for l in text.splitlines()] + [0])
    h = (font.getsize("A")[1] * (len(text.splitlines()) + 1)) + 2 * margin
    w = max_w + 2 * margin
    img = Image.new("RGBA", (w, h), (30, 30, 34, 255))
    draw = ImageDraw.Draw(img)
    draw.text((margin, margin), text, font=font, fill=(230, 230, 230))
    # simple highlight bar
    draw.rectangle([0,0,w,24], fill=(50,50,55,255))
    return img

# ---------- Discord UI: Vote Buttons ----------
class VoteView(discord.ui.View):
    def __init__(self, submission_id: int, timeout=None):
        super().__init__(timeout=timeout)
        self.submission_id = submission_id

    async def update_message_counts(self, interaction: discord.Interaction):
        votes = get_votes(self.submission_id)
        # update embed footer with counts
        try:
            embed = interaction.message.embeds[0]
            embed.set_footer(text=f"Score: {votes['score']} • Votes: {votes['count']} • ID: {self.submission_id}")
            await interaction.message.edit(embed=embed, view=self)
        except Exception:
            pass

    @discord.ui.button(label="Upvote", style=discord.ButtonStyle.green, custom_id="upvote")
    async def upvote(self, interaction: discord.Interaction, button: discord.ui.Button):
        set_vote(self.submission_id, interaction.user.id, 1)
        await interaction.response.send_message("Dein Upvote wurde registriert.", ephemeral=True)
        await self.update_message_counts(interaction)

    @discord.ui.button(label="Downvote", style=discord.ButtonStyle.red, custom_id="downvote")
    async def downvote(self, interaction: discord.Interaction, button: discord.ui.Button):
        set_vote(self.submission_id, interaction.user.id, -1)
        await interaction.response.send_message("Dein Downvote wurde registriert.", ephemeral=True)
        await self.update_message_counts(interaction)

# ---------- Slash commands ----------
@bot.event
async def on_ready():
    print(f"Bot ready as {bot.user} (id: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} commands.")
    except Exception as e:
        print("Sync failed:", e)

@bot.tree.command(name="set_form_channel", description="Setze den Kanal, in den geprüfte Codes gepostet werden (Admin only).")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_form_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    set_form_channel(interaction.guild.id, channel.id)
    await interaction.response.send_message(f"Form-Kanal gesetzt auf {channel.mention}", ephemeral=True)

@bot.tree.command(name="submit_code", description="Sende Code zur Prüfung und (optional) Ausführung.")
@app_commands.describe(language="Programmiersprache (z. B. python, javascript, java)", code="Dein Code (als Markdown oder Plaintext)")
async def submit_code(interaction: discord.Interaction, language: str, code: str):
    await interaction.response.defer(thinking=True)
    guild = interaction.guild
    if not guild:
        await interaction.followup.send("Dieser Befehl kann nur in einem Server verwendet werden.", ephemeral=True)
        return
    form_channel_id = get_form_channel(guild.id)
    if not form_channel_id:
        await interaction.followup.send("Kein Form-Kanal gesetzt. Admins können /set_form_channel benutzen.", ephemeral=True)
        return
    # basic limits
    if len(code) > MAX_CODE_LENGTH:
        await interaction.followup.send(f"Code zu lang (Limit {MAX_CODE_LENGTH} Zeichen).", ephemeral=True)
        return
    # Save initial submission
    submission_id = save_submission(guild.id, interaction.user.id, language, code, status="reviewing")
    # AI static review
    aires = await ai_review_code(code, language)
    risk_score = aires["risk_score"]
    ai_summary = aires["summary"]
    update_submission_result(submission_id, ai_summary=ai_summary)
    if risk_score >= 50:
        update_submission_result(submission_id, status="rejected")
        await interaction.followup.send(f"Code abgelehnt (Risikoscore {risk_score}). Gründe:\n{ai_summary}", ephemeral=True)
        try:
            await interaction.user.send(f"Dein Einreichung (ID {submission_id}) wurde abgelehnt.\nGründe:\n{ai_summary}")
        except Exception:
            pass
        return

    # If low risk -> try to run in sandbox (Piston)
    async with aiohttp.ClientSession() as session:
        try:
            result = await run_code_in_piston(session, language, code, timeout_ms=3000)
        except Exception as e:
            result = {"error": f"Fehler beim Kontakt zur Ausführungs-Instanz: {e}"}

    if "error" in result:
        update_submission_result(submission_id, status="exec_failed", stdout=None, stderr=str(result["error"]))
        await interaction.followup.send(f"Ausführung fehlgeschlagen: {result['error']}\nDie Einreichung wurde aber zur Review-Queue hinzugefügt.", ephemeral=True)
        # Post to form channel as "failed execution" with ai_summary
        channel = bot.get_channel(form_channel_id)
        embed = discord.Embed(title=f"Code Einreichung — ID {submission_id}", color=0xDD8844)
        embed.add_field(name="User", value=interaction.user.mention, inline=True)
        embed.add_field(name="Language", value=language, inline=True)
        embed.add_field(name="Status", value="Exec failed", inline=True)
        embed.add_field(name="AI Summary", value=ai_summary[:1000] if ai_summary else "—", inline=False)
        embed.add_field(name="Note", value=f"Execution error: {result['error'][:1000]}", inline=False)
        await channel.send(embed=embed)
        return

    # result contains 'run' and maybe 'compile'
    run = result.get("run", {})
    stdout = run.get("stdout", "") or ""
    stderr = run.get("stderr", "") or ""
    output = run.get("output", "") or ""
    code_highlight_snippet = "\n".join(code.splitlines()[:20])  # default highlight - first 20 lines
    # pick a 'highlight' line from output if exists (for screenshot)
    highlight_lines = (0, min(20, max(1, len(code.splitlines()))))
    if stdout.strip():
        # if stdout has multiple lines, choose the first non-empty
        for i, line in enumerate(stdout.splitlines()):
            if line.strip():
                # choose the code line at same index if exists
                highlight_lines = (i, min(i+8, len(code.splitlines())))
                break

    # create image "screenshot" of highlight
    img = render_code_highlight_image(code, highlight_lines)
    bio = BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)
    # AI analyze executed run (placeholder)
    ai_analysis = f"Automatische Auswertung der Ausführung:\nExit-Code: {run.get('code')}\nStdout (kurz):\n```\n{stdout[:800]}\n```\nStderr (kurz):\n```\n{stderr[:800]}\n```\n"
    update_submission_result(submission_id, status="completed", ai_summary=ai_analysis, stdout=stdout, stderr=stderr)

    # Post into form channel with embed, image and vote buttons
    channel = bot.get_channel(form_channel_id)
    if not channel:
        await interaction.followup.send("Form-Kanal wurde nicht gefunden (ID gesetzt, aber channel nicht verfügbar).", ephemeral=True)
        return

    embed = discord.Embed(title=f"Code Review — ID {submission_id}", color=0x55FF88)
    embed.add_field(name="User", value=interaction.user.mention, inline=True)
    embed.add_field(name="Language", value=language, inline=True)
    embed.add_field(name="Status", value="Executed & Reviewed", inline=True)
    embed.add_field(name="AI Analysis", value=ai_analysis[:1000] if ai_analysis else "—", inline=False)
    embed.add_field(name="Output (kurz)", value=(stdout or "keine Ausgabe")[:1000], inline=False)
    embed.set_footer(text=f"ID: {submission_id}")

    view = VoteView(submission_id)
    file = discord.File(fp=bio, filename=f"highlight_{submission_id}.png")
    await channel.send(embed=embed, file=file, view=view)

    await interaction.followup.send(f"Dein Code (ID {submission_id}) wurde geprüft und in {channel.mention} veröffentlicht.", ephemeral=True)

# ---------- Error handling for missing perms ----------
@set_form_channel.error
async def set_form_channel_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.errors.MissingPermissions):
        await interaction.response.send_message("Du brauchst Manage Server Berechtigungen um den Form-Kanal zu setzen.", ephemeral=True)
    else:
        await interaction.response.send_message("Fehler: " + str(error), ephemeral=True)

# ---------- run ----------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("Fehler: DISCORD_TOKEN nicht gesetzt in der Umgebung.")
        exit(1)
    init_db()
    bot.run(DISCORD_TOKEN)

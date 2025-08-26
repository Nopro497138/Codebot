# bot.py
"""
Discord bot using Judge0 for sandboxed code execution + AI-like summary (placeholder).
All user-facing messages are embeds and in English.
Environment variables required:
  - DISCORD_TOKEN (required)
  - JUDGE0_URL (required) e.g. https://your-judge0.example.com
Optional:
  - JUDGE0_API_KEY
  - JUDGE0_API_KEY_HEADER (defaults to "X-Auth-Token")
  - DB_PATH (defaults to submissions.db)
  - MAX_CODE_LENGTH
"""

import os
import re
import json
import sqlite3
import textwrap
import asyncio
from io import BytesIO
from typing import Union, Optional, Dict, Any

import aiohttp
from PIL import Image, ImageDraw, ImageFont
import discord
from discord import app_commands
from discord.ext import commands

# ---------- CONFIG ----------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
JUDGE0_URL = os.getenv("JUDGE0_URL")  # e.g. https://judge0.example.com
JUDGE0_API_KEY = os.getenv("JUDGE0_API_KEY")  # optional
JUDGE0_API_KEY_HEADER = os.getenv("JUDGE0_API_KEY_HEADER", "X-Auth-Token")
DB_PATH = os.getenv("DB_PATH", "submissions.db")
MAX_CODE_LENGTH = int(os.getenv("MAX_CODE_LENGTH", "8000"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))  # seconds for Judge0 API calls
# ----------------------------

if not DISCORD_TOKEN:
    print("ERROR: DISCORD_TOKEN not set in environment.")
    raise SystemExit(1)
if not JUDGE0_URL:
    print("ERROR: JUDGE0_URL not set in environment (e.g. https://judge0.example.com).")
    raise SystemExit(1)

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- DB helpers (sqlite synchronous for simplicity) ----------
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

def set_form_channel_db(guild_id: int, channel_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO guild_config(guild_id, form_channel_id) VALUES (?, ?)", (guild_id, channel_id))
    conn.commit()
    conn.close()

def get_form_channel_db(guild_id: int) -> Optional[int]:
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
    if not sets:
        conn.close()
        return
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
    r"\beval\(", r"\bexec\(", r"import\s+os", r"subprocess\.", r"socket\.", r"requests\.",
    r"open\([^)]*['\"]/etc", r"rm\s+-rf", r"os\.remove", r"shutil\.rmtree", r"popen\(",
    r"base64\.b64decode", r"urllib\.request", r"paramiko", r"ctypes\.", r"System\.Diagnostics"
]

def static_risk_check(code: str):
    reasons = []
    score = 0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, code):
            reasons.append(f"Matched suspicious pattern: `{pat}`")
            score += 30
    if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", code):
        reasons.append("Detected long base64-like blob (possible obfuscation).")
        score += 20
    if re.search(r"\b(open|os\.open|Path\()", code) and re.search(r"read|write|w\+|rb", code, re.IGNORECASE):
        reasons.append("Contains file read/write patterns.")
        score += 10
    score = min(100, score)
    return score, reasons

# ---------- Judge0 helpers ----------
def judge0_headers() -> Dict[str, str]:
    hdrs = {"Content-Type": "application/json"}
    if JUDGE0_API_KEY:
        hdrs[JUDGE0_API_KEY_HEADER] = JUDGE0_API_KEY
    return hdrs

async def fetch_judge0_languages(session: aiohttp.ClientSession) -> Optional[list]:
    url = JUDGE0_URL.rstrip("/") + "/languages"
    try:
        async with session.get(url, headers=judge0_headers(), timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                return await resp.json()
            else:
                return None
    except Exception:
        return None

async def find_language_id(session: aiohttp.ClientSession, user_lang: str) -> Optional[int]:
    """
    Resolve a user-supplied language string to Judge0 language_id.
    Strategy: fetch /languages and match by name or by alias.
    """
    langs = await fetch_judge0_languages(session)
    if not langs:
        return None
    target = user_lang.strip().lower()
    # langs: list of objects; try to be flexible
    for lang in langs:
        # lang can have fields like 'id','name','aliases' or 'language' etc.
        values = []
        for k in ("name", "language", "aliases", "version"):
            v = lang.get(k) if isinstance(lang, dict) else None
            if v:
                if isinstance(v, list):
                    values.extend([str(x).lower() for x in v])
                else:
                    values.append(str(v).lower())
        # also ensure id and raw string representation
        if str(lang.get("id", "")).lower() == target:
            return int(lang["id"])
        for val in values:
            if target == val or target in val:
                return int(lang["id"])
    # last resort: try numeric
    if user_lang.isdigit():
        return int(user_lang)
    return None

async def submit_to_judge0(session: aiohttp.ClientSession, language_id: int, code: str) -> Dict[str, Any]:
    """
    Submits code synchronously (wait=true) to Judge0 and returns the JSON response.
    Endpoint: POST {JUDGE0_URL}/submissions?base64_encoded=false&wait=true
    """
    url = JUDGE0_URL.rstrip("/") + "/submissions?base64_encoded=false&wait=true"
    payload = {
        "source_code": code,
        "language_id": language_id,
        "stdin": ""
    }
    async with session.post(url, json=payload, headers=judge0_headers(), timeout=REQUEST_TIMEOUT) as resp:
        text = await resp.text()
        try:
            return json.loads(text)
        except Exception:
            return {"error": f"Judge0 returned non-JSON response (status {resp.status}): {text}"}

# ---------- Create highlight "screenshot" (image) ----------
def render_code_highlight_image(code: str, highlight_lines=(0,5)):
    lines = code.splitlines()
    start, end = highlight_lines
    selected = lines[start:end]
    if not selected:
        selected = lines[:min(10, len(lines))]
    text = "\n".join(selected)
    font_size = 16
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()
    margin = 12
    line_sizes = [font.getsize(l)[0] for l in text.splitlines()] if text.splitlines() else [0]
    max_w = max(line_sizes + [0])
    h = (font.getsize("A")[1] * (len(text.splitlines()) + 1)) + 2 * margin
    w = max_w + 2 * margin
    if w < 200:
        w = 200
    img = Image.new("RGBA", (w, h), (30, 30, 34, 255))
    draw = ImageDraw.Draw(img)
    draw.text((margin, margin), text, font=font, fill=(230, 230, 230))
    draw.rectangle([0,0,w,28], fill=(50,50,55,255))
    return img

# ---------- Discord UI: Vote Buttons ----------
class VoteView(discord.ui.View):
    def __init__(self, submission_id: int, timeout=None):
        super().__init__(timeout=timeout)
        self.submission_id = submission_id

    async def update_message_counts(self, interaction: discord.Interaction):
        votes = get_votes(self.submission_id)
        try:
            embed = interaction.message.embeds[0]
            embed.set_footer(text=f"Score: {votes['score']} • Votes: {votes['count']} • ID: {self.submission_id}")
            await interaction.message.edit(embed=embed, view=self)
        except Exception:
            pass

    @discord.ui.button(label="Upvote", style=discord.ButtonStyle.green, custom_id="upvote")
    async def upvote(self, interaction: discord.Interaction, button: discord.ui.Button):
        set_vote(self.submission_id, interaction.user.id, 1)
        await interaction.response.send_message(embed=discord.Embed(description="Your upvote has been recorded.", color=0x2ECC71), ephemeral=True)
        await self.update_message_counts(interaction)

    @discord.ui.button(label="Downvote", style=discord.ButtonStyle.red, custom_id="downvote")
    async def downvote(self, interaction: discord.Interaction, button: discord.ui.Button):
        set_vote(self.submission_id, interaction.user.id, -1)
        await interaction.response.send_message(embed=discord.Embed(description="Your downvote has been recorded.", color=0xE74C3C), ephemeral=True)
        await self.update_message_counts(interaction)

# ---------- Slash commands ----------
@bot.event
async def on_ready():
    print(f"Bot ready as {bot.user} (id: {bot.user.id})")
    try:
        await bot.tree.sync()
        print("Slash commands synced.")
    except Exception as e:
        print("Command sync failed:", e)

@bot.tree.command(name="set_form_channel", description="Set the channel where reviewed submissions will be posted (Admins only).")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_form_channel(interaction: discord.Interaction, channel: Union[discord.TextChannel, discord.ForumChannel]):
    try:
        set_form_channel_db(interaction.guild.id, channel.id)
        embed = discord.Embed(title="Form Channel Set", description=f"Submissions will be posted in {channel.mention}.", color=0x2ECC71)
        await interaction.response.send_message(embed=embed, ephemeral=True)
    except Exception as e:
        embed = discord.Embed(title="Error", description=f"Could not set form channel: {e}", color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="submit_code", description="Submit code for static review and optional sandboxed execution.")
@app_commands.describe(language="Programming language (name or Judge0 language id)", code="Your code (markdown or plain text).")
async def submit_code(interaction: discord.Interaction, language: str, code: str):
    await interaction.response.defer(thinking=True)
    guild = interaction.guild
    if not guild:
        embed = discord.Embed(title="Error", description="This command can only be used inside a server.", color=0xE74C3C)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    form_channel_id = get_form_channel_db(guild.id)
    if not form_channel_id:
        embed = discord.Embed(title="Form Channel Not Set", description="An admin must run `/set_form_channel` first.", color=0xE67E22)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    if len(code) > MAX_CODE_LENGTH:
        embed = discord.Embed(title="Code Too Long", description=f"Max allowed length is {MAX_CODE_LENGTH} characters.", color=0xE74C3C)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    submission_id = save_submission(guild.id, interaction.user.id, language, code, status="reviewing")

    # static/AI placeholder review
    risk_score, reasons = static_risk_check(code)
    ai_summary = "Automatic summary:\n" + "\n".join(code.splitlines()[:10])
    if reasons:
        ai_summary += "\n\nPotential risks:\n- " + "\n- ".join(reasons)
    update_submission_result(submission_id, ai_summary=ai_summary)

    if risk_score >= 50:
        update_submission_result(submission_id, status="rejected")
        embed = discord.Embed(title="Submission Rejected", color=0xE74C3C)
        embed.add_field(name="Risk Score", value=str(risk_score), inline=True)
        embed.add_field(name="Summary", value=(ai_summary[:1000] if ai_summary else "—"), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        try:
            dm = discord.Embed(title=f"Submission #{submission_id} Rejected", description="Your submission was rejected by automated checks.", color=0xE74C3C)
            dm.add_field(name="Risk Score", value=str(risk_score), inline=True)
            dm.add_field(name="Summary", value=(ai_summary[:1500] if ai_summary else "—"), inline=False)
            await interaction.user.send(embed=dm)
        except Exception:
            pass
        return

    # Resolve language -> judge0 language_id
    async with aiohttp.ClientSession() as session:
        lang_id = await find_language_id(session, language)
        if lang_id is None:
            # Try a helpful fallback: ask Judge0 for available languages (first 20)
            langs = await fetch_judge0_languages(session)
            if langs:
                sample = ", ".join([str(l.get("name") or l.get("language") or l.get("id")) for l in langs[:20]])
            else:
                sample = "Could not fetch languages from Judge0"
            update_submission_result(submission_id, status="lang_not_found")
            embed = discord.Embed(title="Language Not Found", description=f"Could not resolve `{language}` to a Judge0 language id.\n\nSample languages: {sample}", color=0xE67E22)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Submit to Judge0
        try:
            result = await submit_to_judge0(session, lang_id, code)
        except asyncio.TimeoutError:
            result = {"error": "Timeout contacting Judge0"}
        except Exception as e:
            result = {"error": str(e)}

    if "error" in result:
        update_submission_result(submission_id, status="exec_failed", stderr=str(result.get("error")))
        embed = discord.Embed(title="Execution Failed", description="Execution service returned an error.", color=0xE67E22)
        embed.add_field(name="Note", value=str(result.get("error"))[:1500], inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        # Post to form channel as failed execution
        channel = bot.get_channel(form_channel_id)
        if channel:
            post_embed = discord.Embed(title=f"Code Submission — ID {submission_id}", color=0xDD8844)
            post_embed.add_field(name="User", value=interaction.user.mention, inline=True)
            post_embed.add_field(name="Language", value=language, inline=True)
            post_embed.add_field(name="Status", value="Execution failed", inline=True)
            post_embed.add_field(name="AI Summary", value=(ai_summary[:1000] if ai_summary else "—"), inline=False)
            post_embed.add_field(name="Execution Error", value=(result.get("error") or "")[:1500], inline=False)
            await channel.send(embed=post_embed)
        return

    # Parse Judge0 response
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    compile_out = result.get("compile_output") or ""
    status_obj = result.get("status") or {}
    status_desc = status_obj.get("description") or str(status_obj)
    time_used = result.get("time")
    memory_used = result.get("memory")

    # pick highlight lines
    highlight_lines = (0, min(20, max(1, len(code.splitlines()))))
    if stdout.strip():
        for i, line in enumerate(stdout.splitlines()):
            if line.strip():
                highlight_lines = (i, min(i+8, len(code.splitlines())))
                break

    # render highlight image
    img = render_code_highlight_image(code, highlight_lines)
    bio = BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)

    ai_analysis = (
        f"Execution analysis:\nStatus: {status_desc}\n"
        f"Time: {time_used}\nMemory: {memory_used}\n\n"
        f"Stdout (short):\n```\n{stdout[:800]}\n```\n"
        f"Stderr (short):\n```\n{stderr[:800]}\n```\n"
        f"Compile output (short):\n```\n{compile_out[:800]}\n```\n"
    )

    update_submission_result(submission_id, status="completed", ai_summary=ai_analysis, stdout=stdout, stderr=stderr)

    # Post to form channel
    channel = bot.get_channel(form_channel_id)
    if not channel:
        embed = discord.Embed(title="Error", description="Configured form channel could not be found.", color=0xE74C3C)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    post_embed = discord.Embed(title=f"Code Review — ID {submission_id}", color=0x55FF88)
    post_embed.add_field(name="User", value=interaction.user.mention, inline=True)
    post_embed.add_field(name="Language", value=language, inline=True)
    post_embed.add_field(name="Status", value="Executed & Reviewed", inline=True)
    post_embed.add_field(name="AI Analysis (short)", value=(ai_analysis[:1000] if ai_analysis else "—"), inline=False)
    post_embed.add_field(name="Output (short)", value=(stdout or "no output")[:1000], inline=False)
    post_embed.set_footer(text=f"ID: {submission_id}")

    view = VoteView(submission_id)
    file = discord.File(fp=bio, filename=f"highlight_{submission_id}.png")
    await channel.send(embed=post_embed, file=file, view=view)

    confirm_embed = discord.Embed(title="Submission Posted", description=f"Your submission (ID {submission_id}) was reviewed and posted to {channel.mention}.", color=0x2ECC71)
    await interaction.followup.send(embed=confirm_embed, ephemeral=True)

@set_form_channel.error
async def set_form_channel_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.errors.MissingPermissions):
        embed = discord.Embed(title="Permission Required", description="You need the Manage Server permission to set the form channel.", color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)
    else:
        embed = discord.Embed(title="Error", description=str(error), color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)

# ---------- Run ----------
if __name__ == "__main__":
    init_db()
    bot.run(DISCORD_TOKEN)

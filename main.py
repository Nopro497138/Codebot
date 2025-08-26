# bot.py
# NOTE: keep your DISCORD_TOKEN and PISTON_URL in environment variables (.env or Railway env)
import os
import re
import sqlite3
import aiohttp
import asyncio
from io import BytesIO
from typing import Union

from PIL import Image, ImageDraw, ImageFont
import discord
from discord import app_commands
from discord.ext import commands

# ---------- CONFIG ----------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
PISTON_URL = os.getenv("PISTON_URL", "http://localhost:2000")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # optional, placeholder for AI review integration
DB_PATH = os.getenv("DB_PATH", "submissions.db")
MAX_CODE_LENGTH = int(os.getenv("MAX_CODE_LENGTH", "8000"))
# ----------------------------

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- DB helpers (sqlite) ----------
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

def get_form_channel_db(guild_id: int):
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
    r"\beval\(", r"\bexec\(", r"import\s+os", r"subprocess\.", r"socket\.", r"requests\.", r"ftplib\.",
    r"open\([^)]*['\"]/etc", r"rm\s+-rf", r"os\.remove", r"shutil\.rmtree", r"popen\(", r"base64\.b64decode",
    r"urllib\.request", r"paramiko", r"ctypes\.", r"System\.Diagnostics", r"Process\.Start", r"CreateRemoteThread"
]

def static_risk_check(code: str):
    """Very simple heuristic scanner. Returns (risk_level:int 0-100, reasons:list)."""
    reasons = []
    score = 0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, code):
            reasons.append(f"Matched suspicious pattern: `{pat}`")
            score += 30
    if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", code):  # base64-like long blob heuristic
        reasons.append("Detected long base64-like blob (possible obfuscation).")
        score += 20
    if re.search(r"\b(open|os\.open|Path\()", code) and re.search(r"read|write|w\+|rb", code, re.IGNORECASE):
        reasons.append("Contains file read/write patterns.")
        score += 10
    score = min(100, score)
    return score, reasons

# ---------- AI review placeholder ----------
async def ai_review_code(code: str, language: str) -> dict:
    """
    Placeholder for AI review. Combine static heuristics + simple summary.
    Return: { "risk_score": int(0-100), "summary": str }
    """
    risk_score, reasons = static_risk_check(code)
    summary = "Auto-summary:\n"
    first_lines = "\n".join(code.splitlines()[:10])
    summary += f"First lines:\n```\n{first_lines}\n```\n"
    if reasons:
        summary += "Potential risks:\n- " + "\n- ".join(reasons)
    else:
        summary += "No obvious static risk markers found."
    return {"risk_score": risk_score, "summary": summary}

# ---------- Piston execution ----------
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
    try:
        async with session.post(url, json=payload, timeout=15) as resp:
            if resp.status != 200:
                text = await resp.text()
                return {"error": f"Piston returned status {resp.status}: {text}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "Timeout while contacting Piston execution service."}
    except Exception as e:
        return {"error": f"Error contacting Piston: {e}"}

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
    # calculate size (fallbacks handled)
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
        await interaction.response.send_message("Your upvote has been recorded.", ephemeral=True)
        await self.update_message_counts(interaction)

    @discord.ui.button(label="Downvote", style=discord.ButtonStyle.red, custom_id="downvote")
    async def downvote(self, interaction: discord.Interaction, button: discord.ui.Button):
        set_vote(self.submission_id, interaction.user.id, -1)
        await interaction.response.send_message("Your downvote has been recorded.", ephemeral=True)
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

@bot.tree.command(name="set_form_channel", description="Set the channel where reviewed submissions will be posted (Admins only).")
@app_commands.checks.has_permissions(manage_guild=True)
async def set_form_channel(interaction: discord.Interaction, channel: Union[discord.TextChannel, discord.ForumChannel]):
    # Accept TextChannel or ForumChannel
    try:
        set_form_channel_db(interaction.guild.id, channel.id)
        embed = discord.Embed(title="Form Channel Set", description=f"Submissions will be posted in {channel.mention}.", color=0x2ECC71)
        await interaction.response.send_message(embed=embed, ephemeral=True)
    except Exception as e:
        embed = discord.Embed(title="Error", description=f"Could not set form channel: {e}", color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="submit_code", description="Submit code for AI review and optional sandboxed execution.")
@app_commands.describe(language="Programming language (e.g. python, javascript, java)", code="Your code (markdown or plain text).")
async def submit_code(interaction: discord.Interaction, language: str, code: str):
    await interaction.response.defer(thinking=True)
    guild = interaction.guild
    if not guild:
        embed = discord.Embed(title="Error", description="This command can only be used in a server.", color=0xE74C3C)
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

    # Save initial submission
    submission_id = save_submission(guild.id, interaction.user.id, language, code, status="reviewing")

    # AI static review
    aires = await ai_review_code(code, language)
    risk_score = aires["risk_score"]
    ai_summary = aires["summary"]
    update_submission_result(submission_id, ai_summary=ai_summary)

    if risk_score >= 50:
        update_submission_result(submission_id, status="rejected")
        embed = discord.Embed(title="Submission Rejected", color=0xE74C3C)
        embed.add_field(name="Risk Score", value=str(risk_score), inline=True)
        embed.add_field(name="Reason (summary)", value=(ai_summary[:1000] if ai_summary else "—"), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        # try to DM the user with the reason
        try:
            dm_embed = discord.Embed(title=f"Submission #{submission_id} Rejected", description="Your submission was rejected by the automated review.", color=0xE74C3C)
            dm_embed.add_field(name="Risk Score", value=str(risk_score), inline=True)
            dm_embed.add_field(name="Summary", value=(ai_summary[:1500] if ai_summary else "—"), inline=False)
            await interaction.user.send(embed=dm_embed)
        except Exception:
            pass
        return

    # Low risk -> attempt sandboxed run via Piston
    async with aiohttp.ClientSession() as session:
        try:
            result = await run_code_in_piston(session, language, code, timeout_ms=3000)
        except Exception as e:
            result = {"error": f"Error contacting execution service: {e}"}

    if "error" in result:
        update_submission_result(submission_id, status="exec_failed", stdout=None, stderr=str(result["error"]))
        embed = discord.Embed(title="Execution Failed", description="Execution service returned an error.", color=0xE67E22)
        embed.add_field(name="Note", value=(result["error"][:1500]), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

        # Post to form channel as failed execution
        channel = bot.get_channel(form_channel_id)
        if channel:
            post_embed = discord.Embed(title=f"Code Submission — ID {submission_id}", color=0xDD8844)
            post_embed.add_field(name="User", value=interaction.user.mention, inline=True)
            post_embed.add_field(name="Language", value=language, inline=True)
            post_embed.add_field(name="Status", value="Execution failed", inline=True)
            post_embed.add_field(name="AI Summary", value=(ai_summary[:1000] if ai_summary else "—"), inline=False)
            post_embed.add_field(name="Execution Error", value=(result["error"][:1500]), inline=False)
            await channel.send(embed=post_embed)
        return

    # Successful execution result processing
    run = result.get("run", {}) or {}
    stdout = run.get("stdout", "") or ""
    stderr = run.get("stderr", "") or ""
    highlight_lines = (0, min(20, max(1, len(code.splitlines()))))
    if stdout.strip():
        for i, line in enumerate(stdout.splitlines()):
            if line.strip():
                highlight_lines = (i, min(i+8, len(code.splitlines())))
                break

    # Render highlight image
    img = render_code_highlight_image(code, highlight_lines)
    bio = BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)

    ai_analysis = f"Execution analysis:\nExit Code: {run.get('code')}\nStdout (short):\n```\n{stdout[:800]}\n```\nStderr (short):\n```\n{stderr[:800]}\n```\n"
    update_submission_result(submission_id, status="completed", ai_summary=ai_analysis, stdout=stdout, stderr=stderr)

    # Post into the configured form channel
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

    # confirmation to the submitter
    confirm_embed = discord.Embed(title="Submission Posted", description=f"Your submission (ID {submission_id}) was reviewed and posted to {channel.mention}.", color=0x2ECC71)
    await interaction.followup.send(embed=confirm_embed, ephemeral=True)

# ---------- Error handling for missing perms ----------
@set_form_channel.error
async def set_form_channel_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.errors.MissingPermissions):
        embed = discord.Embed(title="Permission Required", description="You need the Manage Server permission to set the form channel.", color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)
    else:
        embed = discord.Embed(title="Error", description=str(error), color=0xE74C3C)
        await interaction.response.send_message(embed=embed, ephemeral=True)

# ---------- run ----------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("ERROR: DISCORD_TOKEN not set in environment.")
        raise SystemExit(1)
    init_db()
    bot.run(DISCORD_TOKEN)

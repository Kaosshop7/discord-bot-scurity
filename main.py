import discord
from discord.ext import commands, tasks
from discord import app_commands
import datetime
import json
import os
import re
import sqlite3
import asyncio
import psutil
import logging
import threading
from flask import Flask
from collections import defaultdict
from dotenv import load_dotenv

# ==========================================
# ⚙️ INITIALIZATION & CONFIG
# ==========================================
# โหลดค่าจาก .env (สำหรับรันในคอม)
load_dotenv()

# ดึง Token จาก Environment Variable (รองรับทั้ง .env และ Render)
TOKEN = os.getenv('TOKEN')
OWNER_ID = 1228316351945506847 # ⚠️ แก้เป็น ID ของคุณ

DB_FILE = "protection.db"

# Limits & Thresholds
SPAM_THRESHOLD = 5      # 5 ข้อความ
SPAM_TIME = 5           # ภายใน 5 วินาที
NUKE_THRESHOLD = 3      # 3 การกระทำ
NUKE_TIME = 10          # ภายใน 10 วินาที

# Regex Patterns
URL_PATTERN = r'(https?://|www\.|discord\.(gg|io|me|li)|discordapp\.com/invite)'
DISCORD_INVITE_PATTERN = r'(discord\.(gg|io|me|li)|discordapp\.com/invite|discord\.com/invite)'

# Colors
COLOR_SUCCESS = 0x00ff00
COLOR_ERROR = 0xff0000
COLOR_WARN = 0xffa500
COLOR_INFO = 0x00b0f4

# ==========================================
# 🌐 KEEP ALIVE SERVER (Flask)
# ==========================================
app = Flask('')

@app.route('/')
def home():
    return "<h1>🛡️ PDR Security is Running...</h1>"

def run_web_server():
    # Render จะส่ง PORT มาให้ หรือใช้ 8080
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)

def keep_alive():
    t = threading.Thread(target=run_web_server)
    t.start()

# ==========================================
# 🗄️ DATABASE MANAGER (SQLite)
# ==========================================
class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY, type TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS backups (guild_id INTEGER, data TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
        self.conn.commit()

    def get_config(self, default):
        self.cursor.execute("SELECT value FROM config WHERE key='main_config'")
        res = self.cursor.fetchone()
        if not res: return default
        
        # Merge Config (ป้องกัน Key หาย)
        data = json.loads(res[0])
        for k, v in default.items():
            if k not in data: data[k] = v
        for k, v in default["modules"].items():
            if k not in data["modules"]: data["modules"][k] = v
        return data

    def save_config(self, data):
        self.cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ('main_config', json.dumps(data)))
        self.conn.commit()

    def manage_whitelist(self, tid, ttype, action):
        if action == "add":
            try:
                self.cursor.execute("INSERT INTO whitelist (id, type) VALUES (?, ?)", (tid, ttype))
                self.conn.commit()
                return True
            except: return False
        elif action == "remove":
            self.cursor.execute("DELETE FROM whitelist WHERE id=?", (tid,))
            self.conn.commit()
            return True
        elif action == "list":
            self.cursor.execute("SELECT id, type FROM whitelist")
            return self.cursor.fetchall()

    def backup_guild(self, guild_id, data):
        self.cursor.execute("INSERT INTO backups (guild_id, data) VALUES (?, ?)", (guild_id, json.dumps(data)))
        self.conn.commit()

    def get_backup(self, guild_id):
        self.cursor.execute("SELECT data FROM backups WHERE guild_id=? ORDER BY timestamp DESC LIMIT 1", (guild_id,))
        res = self.cursor.fetchone()
        return json.loads(res[0]) if res else None

db = Database()

# Default Configuration
default_conf = {
    "modules": {
        "anti_spam": {"enable": True, "action": "timeout"},
        "anti_nuke": {"enable": True, "action": "ban"},
        "anti_bot": {"enable": True, "action": "kick"},
        "anti_role": {"enable": True, "action": "ban"},
        "anti_invite": {"enable": True, "action": "kick"},
        "anti_mention": {"enable": True, "action": "timeout"},
        "anti_link": {"enable": True, "action": "kick"},
        "anti_webhook": {"enable": True, "action": "ban"}
    },
    "log_channel": None
}

current_config = db.get_config(default_conf)

# ==========================================
# 🤖 BOT SETUP & MONITORING
# ==========================================
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

spam_tracker = defaultdict(list)
nuke_tracker = defaultdict(lambda: defaultdict(list))

# Rate Limit Handling Variables
STATUS_UPDATE_INTERVAL = 30
BACKOFF_DELAY = 60

@tasks.loop(seconds=STATUS_UPDATE_INTERVAL)
async def update_status_task():
    try:
        # Resource Monitor
        latency = round(bot.latency * 1000)
        process = psutil.Process(os.getpid())
        ram_usage = process.memory_info().rss / 1024 / 1024 # MB
        
        status_text = f"🛡️ PDR Security by. sxru7._ | RAM: {ram_usage:.1f}MB | Ping: {latency}ms"
        
        await bot.change_presence(
            activity=discord.Activity(type=discord.ActivityType.protecting, name=status_text),
            status=discord.Status.online
        )
    except discord.HTTPException as e:
        if e.status == 429: # Rate Limit Handler
            print(f"⚠️ Rate Limit Hit! Backing off {BACKOFF_DELAY}s")
            update_status_task.change_interval(seconds=BACKOFF_DELAY)
            await asyncio.sleep(BACKOFF_DELAY)
            update_status_task.change_interval(seconds=STATUS_UPDATE_INTERVAL)
    except Exception as e:
        print(f"Status Error: {e}")

@update_status_task.before_loop
async def before_status_update():
    await bot.wait_until_ready()

# ==========================================
# 🛠️ HELPER FUNCTIONS
# ==========================================
def is_whitelisted(member):
    if member.id == OWNER_ID or member.id == bot.user.id: return True
    wl = db.manage_whitelist(None, None, "list")
    wl_ids = [item[0] for item in wl]
    
    if member.id in wl_ids: return True
    if hasattr(member, "roles"):
        for role in member.roles:
            if role.id in wl_ids: return True
    return False

async def send_log(guild, title, description, color=COLOR_ERROR, user=None):
    if not current_config["log_channel"]: return
    try:
        channel = guild.get_channel(current_config["log_channel"])
        if channel:
            embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.datetime.now())
            if user: embed.set_author(name=f"{user} ({user.id})", icon_url=user.avatar.url if user.avatar else None)
            embed.set_footer(text="PDR Security System")
            await channel.send(embed=embed)
    except: pass

async def create_backup(guild):
    roles = []
    for role in guild.roles:
        if role.is_default(): continue
        roles.append({
            "name": role.name,
            "permissions": role.permissions.value,
            "color": role.color.value,
            "hoist": role.hoist,
            "mentionable": role.mentionable
        })
    db.backup_guild(guild.id, {"roles": roles})

async def execute_punishment(member, action, reason):
    try:
        if action == "ban":
            await member.ban(reason=reason)
            return "🚫 BANNED"
        elif action == "kick":
            await member.kick(reason=reason)
            return "👢 KICKED"
        elif action == "timeout":
            if member.bot: 
                await member.kick(reason=reason)
                return "👢 KICKED (Bot)"
            await member.timeout(datetime.timedelta(minutes=10), reason=reason)
            return "🔇 TIMEOUT"
        return "⚠️ WARNED"
    except: return "❌ FAILED (No Perms)"

# ==========================================
# 💻 SLASH COMMANDS
# ==========================================
ACTION_CHOICES = [
    app_commands.Choice(name="Ban", value="ban"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Timeout", value="timeout"),
    app_commands.Choice(name="None (Log Only)", value="none")
]

# 1. Ping
@bot.tree.command(name="ping", description="เช็คสถานะ, RAM และ Ping ของบอท")
async def cmd_ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    process = psutil.Process(os.getpid())
    ram = process.memory_info().rss / 1024 / 1024
    
    embed = discord.Embed(title="🏓 Pong!", color=COLOR_SUCCESS)
    embed.add_field(name="Ping", value=f"`{latency}ms`", inline=True)
    embed.add_field(name="RAM Usage", value=f"`{ram:.2f}MB`", inline=True)
    embed.set_footer(text=f"PDR Security by. sxru7._")
    await interaction.response.send_message(embed=embed, ephemeral=True)

# 2. Help
@bot.tree.command(name="help", description="ดูรายการคำสั่งทั้งหมด")
async def cmd_help(interaction: discord.Interaction):
    embed = discord.Embed(title="🛡️ PDR Security Commands", description="รายการคำสั่งทั้งหมด (Visible only to you)", color=COLOR_INFO)
    embed.add_field(name="⚙️ General", value="`/setup` - เปิดใช้งานทุกระบบ\n`/ping` - เช็คสถานะ\n`/set_log` - ตั้งห้องแจ้งเตือน", inline=False)
    embed.add_field(name="🛡️ Protection Config", value="`/anti_spam` `/anti_nuke` `/anti_bot`\n`/anti_invite` `/anti_link_name` `/anti_mention`\n`/anti_webhook`", inline=False)
    embed.add_field(name="🚨 Emergency", value="`/lockdown` - ปิดตายเซิร์ฟ\n`/unlockdown` - เปิดเซิร์ฟ\n`/backup` - สำรองยศ\n`/whitelist` - จัดการคนยกเว้น", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# 3. Setup (Public)
@bot.tree.command(name="setup", description="เปิดใช้งานระบบป้องกันทั้งหมด (Enable All)")
@app_commands.checks.has_permissions(administrator=True)
async def cmd_setup(interaction: discord.Interaction):
    global current_config
    for key in current_config["modules"]:
        current_config["modules"][key]["enable"] = True
    db.save_config(current_config)
    
    embed = discord.Embed(title="🛡️ PDR Security Online", description="**Status: ACTIVE**\nAll protection modules have been enabled.", color=COLOR_SUCCESS)
    embed.add_field(name="Modules", value="`Anti-Nuke`, `Anti-Spam`, `Anti-Bot`, `Anti-Webhook`,\n`Anti-Invite`, `Anti-Link`, `Anti-Mention`", inline=False)
    embed.set_thumbnail(url=bot.user.avatar.url if bot.user.avatar else None)
    embed.set_footer(text="Security by. sxru7._")
    await interaction.response.send_message(embed=embed, ephemeral=False)

# 4. Anti Config Commands
async def update_config(interaction, module, status, action, name):
    current_config["modules"][module] = {"enable": status, "action": action.value}
    db.save_config(current_config)
    embed = discord.Embed(title=f"⚙️ {name} Updated", color=COLOR_INFO)
    embed.add_field(name="Status", value="✅ Enabled" if status else "❌ Disabled", inline=True)
    embed.add_field(name="Action", value=f"**{action.name}**", inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="anti_webhook", description="ตั้งค่าป้องกัน Webhook Spam")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_webhook(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_webhook", status, action, "Anti-Webhook")

@bot.tree.command(name="anti_spam", description="ตั้งค่า Anti-Spam")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_spam(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_spam", status, action, "Anti-Spam")

@bot.tree.command(name="anti_invite", description="ตั้งค่า Anti-Invite")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_invite(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_invite", status, action, "Anti-Invite")

@bot.tree.command(name="anti_mention", description="ตั้งค่า Anti-Mention")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_mention(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_mention", status, action, "Anti-Mention")

@bot.tree.command(name="anti_bot", description="ตั้งค่า Anti-Bot")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_bot(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_bot", status, action, "Anti-Bot Add")

@bot.tree.command(name="anti_link_name", description="ตั้งค่า Anti-Link Name")
@app_commands.choices(action=ACTION_CHOICES)
async def cmd_link(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_link", status, action, "Anti-Link Name")

@bot.tree.command(name="anti_nuke", description="ตั้งค่า Anti-Nuke")
@app_commands.choices(action=[app_commands.Choice(name="Ban", value="ban"), app_commands.Choice(name="Kick", value="kick")])
async def cmd_nuke(interaction: discord.Interaction, status: bool, action: app_commands.Choice[str]):
    await update_config(interaction, "anti_nuke", status, action, "Anti-Nuke")

# 5. Lockdown / Backup / Whitelist
@bot.tree.command(name="lockdown", description="🔒 EMERGENCY: ปิดตายเซิร์ฟเวอร์")
@app_commands.checks.has_permissions(administrator=True)
async def cmd_lockdown(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    for channel in interaction.guild.text_channels:
        try: await channel.set_permissions(interaction.guild.default_role, send_messages=False)
        except: pass
    
    embed = discord.Embed(title="🔒 Lockdown Activated", description="Server has been locked down.", color=COLOR_WARN)
    await interaction.followup.send(embed=embed)
    await send_log(interaction.guild, "🔒 Lockdown Enabled", f"Admin: {interaction.user.mention}")

@bot.tree.command(name="unlockdown", description="🔓 ยกเลิก Lockdown")
@app_commands.checks.has_permissions(administrator=True)
async def cmd_unlockdown(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    for channel in interaction.guild.text_channels:
        try: await channel.set_permissions(interaction.guild.default_role, send_messages=True)
        except: pass
    
    embed = discord.Embed(title="🔓 Lockdown Lifted", description="Server is back to normal.", color=COLOR_SUCCESS)
    await interaction.followup.send(embed=embed)

@bot.tree.command(name="whitelist", description="จัดการ Whitelist")
@app_commands.choices(action=[app_commands.Choice(name="Add", value="add"), app_commands.Choice(name="Remove", value="remove"), app_commands.Choice(name="List", value="list")])
async def cmd_whitelist(interaction: discord.Interaction, action: app_commands.Choice[str], target: discord.User = None, role: discord.Role = None):
    if interaction.user.id != OWNER_ID: return await interaction.response.send_message("❌ Owner Only", ephemeral=True)
    
    if action.value == "list":
        wl = db.manage_whitelist(None, None, "list")
        embed = discord.Embed(title="📜 Whitelist Database", description=str(wl), color=COLOR_INFO)
        return await interaction.response.send_message(embed=embed, ephemeral=True)

    tid = target.id if target else role.id
    ttype = "user" if target else "role"
    
    res = db.manage_whitelist(tid, ttype, action.value)
    embed = discord.Embed(title="✅ Success" if res else "❌ Failed", description=f"Action: {action.name} {tid}", color=COLOR_SUCCESS if res else COLOR_ERROR)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="set_log", description="ตั้งห้อง Log")
async def cmd_set_log(interaction: discord.Interaction, channel: discord.TextChannel):
    current_config["log_channel"] = channel.id
    db.save_config(current_config)
    embed = discord.Embed(title="📝 Log Channel Set", description=f"Channel: {channel.mention}", color=COLOR_SUCCESS)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="backup", description="สำรองข้อมูลยศ (Manual Backup)")
@app_commands.checks.has_permissions(administrator=True)
async def cmd_backup(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await create_backup(interaction.guild)
    embed = discord.Embed(title="💾 Backup Complete", color=COLOR_SUCCESS)
    await interaction.followup.send(embed=embed)

# ==========================================
# 🚨 EVENT HANDLERS (LOGIC)
# ==========================================

@bot.event
async def on_ready():
    print(f"🔥 Bot Online: {bot.user}")
    print("------------------------------")
    if not update_status_task.is_running():
        update_status_task.start()
    
    try:
        await bot.tree.sync()
        print("✅ Slash Commands Synced")
    except Exception as e:
        print(f"❌ Sync Error: {e}")
        
    for guild in bot.guilds: await create_backup(guild)

@bot.event
async def on_message(message):
    if message.author.bot or is_whitelisted(message.author): return
    cfg = current_config["modules"]

    # Anti-Invite
    if cfg["anti_invite"]["enable"] and re.search(DISCORD_INVITE_PATTERN, message.content, re.IGNORECASE):
        await message.delete()
        res = await execute_punishment(message.author, cfg["anti_invite"]["action"], "Anti-Invite")
        await send_log(message.guild, "🚫 Invite Blocked", f"User: {message.author.mention}\nAction: **{res}**", user=message.author)
        return
    
    # Anti-Mention
    if cfg["anti_mention"]["enable"] and message.mention_everyone:
        await message.delete()
        res = await execute_punishment(message.author, cfg["anti_mention"]["action"], "Mass Mention")
        await send_log(message.guild, "⚠️ Mass Mention", f"User: {message.author.mention}\nAction: **{res}**", user=message.author)
        return

    # Anti-Spam
    if cfg["anti_spam"]["enable"]:
        uid = message.author.id
        now = datetime.datetime.now()
        spam_tracker[uid].append(now)
        spam_tracker[uid] = [t for t in spam_tracker[uid] if (now - t).total_seconds() < SPAM_TIME]
        
        if len(spam_tracker[uid]) >= SPAM_THRESHOLD:
            try: await message.channel.purge(limit=SPAM_THRESHOLD, check=lambda m: m.author.id == uid)
            except: pass
            
            res = await execute_punishment(message.author, cfg["anti_spam"]["action"], "Anti-Spam")
            await send_log(message.guild, "🔇 Spam Detected", f"User: {message.author.mention}\nAction: **{res}**", user=message.author)
            spam_tracker[uid] = []

    await bot.process_commands(message)

# 🔥 Anti-Webhook Logic
@bot.event
async def on_webhooks_update(channel):
    if not current_config["modules"]["anti_webhook"]["enable"]: return
    await asyncio.sleep(0.5) 
    async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create):
        if is_whitelisted(entry.user): return
        
        webhooks = await channel.webhooks()
        for wh in webhooks:
            if wh.user.id == entry.user.id:
                try: await wh.delete(reason="Anti-Webhook")
                except: pass
        
        res = await execute_punishment(entry.user, current_config["modules"]["anti_webhook"]["action"], "Anti-Webhook")
        await send_log(channel.guild, "🎣 Anti-Webhook", f"Creator: {entry.user.mention}\nAction: **{res}**", user=entry.user)
        break

# 🔥 Auto-Recovery Role
@bot.event
async def on_guild_role_delete(role):
    await asyncio.sleep(0.5)
    async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
        if is_whitelisted(entry.user): return
        
        try: await role.guild.ban(entry.user, reason="Deleting Roles")
        except: pass
        
        await send_log(role.guild, "🚨 Role Deleted", f"User: {entry.user.mention}\nRole: {role.name}\nAction: **BANNED**")
        break
    
    backup = db.get_backup(role.guild.id)
    if backup:
        role_data = next((r for r in backup["roles"] if r["name"] == role.name), None)
        if role_data:
            try:
                await role.guild.create_role(name=role_data["name"], permissions=discord.Permissions(role_data["permissions"]), color=discord.Color(role_data["color"]), hoist=role_data["hoist"], mentionable=role_data["mentionable"])
            except: pass

@bot.event
async def on_member_join(member):
    # Anti-Link Name
    if current_config["modules"]["anti_link"]["enable"] and not is_whitelisted(member):
        if re.search(URL_PATTERN, member.display_name, re.IGNORECASE):
            try: await member.edit(nick=f"Moderated-{member.discriminator}")
            except: pass
            res = await execute_punishment(member, current_config["modules"]["anti_link"]["action"], "Bad Nickname")
            await send_log(member.guild, "⚠️ Bad Name", f"User: {member.mention}\nAction: **{res}**")

    # Anti-Bot
    if current_config["modules"]["anti_bot"]["enable"] and member.bot:
        await asyncio.sleep(0.5)
        async for entry in member.guild.audit_logs(limit=1, action=discord.AuditLogAction.bot_add):
            if not is_whitelisted(entry.user):
                try: await member.kick()
                except: pass
                res = await execute_punishment(entry.user, current_config["modules"]["anti_bot"]["action"], "Unauthorized Bot")
                await send_log(member.guild, "🤖 Bot Added", f"Bot: {member.mention}\nAdded by: {entry.user.mention}\nAction: **{res}**")
            break

@bot.event
async def on_member_ban(guild, user):
    if not current_config["modules"]["anti_nuke"]["enable"]: return
    await asyncio.sleep(0.5)
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
        if is_whitelisted(entry.user): return
        key = f"{guild.id}-{entry.user.id}-ban"
        nuke_tracker[key][entry.user.id].append(datetime.datetime.now())
        if len(nuke_tracker[key][entry.user.id]) >= NUKE_THRESHOLD:
            try: await guild.ban(entry.user, reason="Anti-Nuke: Mass Ban")
            except: pass
            await send_log(guild, "🚨 Anti-Nuke", f"Banned {entry.user.mention} for Mass Ban")
        break

@bot.event
async def on_member_update(before, after):
    if not current_config["modules"]["anti_role"]["enable"]: return
    if len(before.roles) < len(after.roles):
        new_roles = [r for r in after.roles if r not in before.roles]
        dangerous = ["administrator", "manage_guild", "ban_members"]
        for role in new_roles:
            if any(value and perm in dangerous for perm, value in role.permissions):
                async for entry in after.guild.audit_logs(limit=1, action=discord.AuditLogAction.member_role_update):
                    if not is_whitelisted(entry.user):
                        try: await after.remove_roles(role)
                        except: pass
                        try: await after.guild.ban(entry.user, reason="Anti-Role Security")
                        except: pass
                        await send_log(after.guild, "🚨 Anti-Role", f"Banned {entry.user.mention} for giving Admin.")
                    break

# ==========================================
# 🏁 RUNNER
# ==========================================
if __name__ == "__main__":
    if TOKEN:
        keep_alive() # Run Flask
        bot.run(TOKEN)
    else:
        print("❌ Error: TOKEN not found in .env or Environment Variables")

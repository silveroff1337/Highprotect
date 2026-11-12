import json
import logging
import os
from datetime import timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile

import discord
from discord.ext import commands


config_path = Path(__file__).with_name("config.json")
with config_path.open(encoding="utf-8") as file:
    config = json.load(file)

whitelist = set(config["WHITELIST_USER_IDS"])
threshold_count = config["THRESHOLD_COUNT"]
window = timedelta(seconds=config["THRESHOLD_SECONDS"])
if threshold_count < 0 or window <= timedelta(0):
    raise ValueError("THRESHOLD_COUNT должен быть >= 0, THRESHOLD_SECONDS > 0")

intents = discord.Intents.default()
intents.members = True
intents.moderation = True
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)
logger = logging.getLogger(__name__)

audit_retention = max(window, timedelta(minutes=1))
next_audit_cleanup = discord.utils.utcnow()
seen_entries = {}
actions = {}
sanctions_in_progress = set()

action_labels = {
    discord.AuditLogAction.channel_delete: "Удаление канала",
    discord.AuditLogAction.channel_create: "Создание канала",
    discord.AuditLogAction.role_delete: "Удаление роли",
    discord.AuditLogAction.role_create: "Создание роли",
    discord.AuditLogAction.role_update: "Изменение разрешений роли",
    discord.AuditLogAction.overwrite_create: "Добавление разрешений канала",
    discord.AuditLogAction.overwrite_update: "Изменение разрешений канала",
    discord.AuditLogAction.overwrite_delete: "Удаление разрешений канала",
    discord.AuditLogAction.ban: "Бан участника",
    discord.AuditLogAction.kick: "Кик участника",
    discord.AuditLogAction.webhook_create: "Создание вебхука",
    discord.AuditLogAction.webhook_delete: "Удаление вебхука",
}


async def sanction(guild, actor_id, count, action, target_id):
    reason = f"Anti-Nuke: {count} действий за {config['THRESHOLD_SECONDS']} с"
    role_status = "снято 0"
    ban_status = "не выполнен"
    member = guild.get_member(actor_id)
    try:
        me = guild.me
        if member is not None and (me is None or member.top_role >= me.top_role):
            ban_status = "недоступен по иерархии ролей"
        else:
            try:
                await guild.ban(discord.Object(id=actor_id), reason=reason, delete_message_seconds=0)
                ban_status = "выдан"
                role_status = "участник забанен"
            except discord.Forbidden:
                ban_status = "Discord отказал в доступе"
            except discord.HTTPException as error:
                ban_status = f"ошибка HTTP {error.status}"

        if member is None and ban_status != "выдан":
            try:
                member = await guild.fetch_member(actor_id)
            except discord.NotFound:
                role_status = "участник покинул сервер"

        if member is not None and ban_status != "выдан":
            removed = failed = skipped = 0
            for role in member.roles:
                if role.is_default():
                    continue
                if role.managed or me is None or role >= me.top_role:
                    skipped += 1
                    continue
                try:
                    await member.remove_roles(role, reason=reason)
                    removed += 1
                except discord.Forbidden:
                    failed += 1
                    logger.warning("Нет прав снять роль %s у %s", role.id, actor_id)
                except discord.HTTPException:
                    failed += 1
                    logger.exception("Ошибка снятия роли %s у %s", role.id, actor_id)
            role_status = f"снято {removed}, ошибок {failed}, недоступных ролей {skipped}"

    except discord.Forbidden:
        role_status = "Discord запретил получить участника"
    except discord.HTTPException as error:
        role_status = f"ошибка получения участника, HTTP {error.status}"

    message = f"{reason}. Исполнитель: `{actor_id}`. Роли: {role_status}. Бан: {ban_status}."
    logger.warning("Сервер %s. %s", guild.id, message)
    channel_id = config.get("LOG_CHANNEL_IDS", {}).get(str(guild.id), config["LOG_CHANNEL_ID"])
    channel = guild.get_channel_or_thread(channel_id)
    if not isinstance(channel, discord.abc.Messageable):
        logger.warning("Канал отчётов %s недоступен на сервере %s", channel_id, guild.id)
        return

    embed = discord.Embed(
        title="СРАБОТАЛА ЗАЩИТА ANTI-NUKE",
        description=f"**Роли:** {role_status}\n**Бан:** {ban_status}",
        color=0xFF0000,
    )
    mention = member.mention if member is not None else f"<@{actor_id}>"
    embed.add_field(name="Нарушитель", value=mention, inline=False)
    action_text = action_labels[action]
    if target_id is not None:
        action_text += f" · ID цели `{target_id}`"
    embed.add_field(name="Действие", value=action_text, inline=False)
    embed.add_field(name="Количество", value=f"{count} действий за {config['THRESHOLD_SECONDS']} с")
    embed.add_field(name="Время", value=discord.utils.format_dt(discord.utils.utcnow(), "F"))

    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.Forbidden:
        logger.warning("Нет прав отправить Embed в канал %s", channel_id)
    except discord.NotFound:
        logger.warning("Канал отчётов %s не найден", channel_id)
    except discord.HTTPException:
        logger.exception("Ошибка отправки отчёта в канал %s", channel_id)


@bot.event
async def on_audit_log_entry_create(entry):
    global next_audit_cleanup

    action = entry.action
    if action not in action_labels:
        return
    if action is discord.AuditLogAction.role_update and not hasattr(entry.after, "permissions"):
        return

    guild = entry.guild
    actor_id = entry.user_id
    if actor_id is None or actor_id in (guild.owner_id, bot.user.id) or actor_id in whitelist:
        return

    now = discord.utils.utcnow()
    cutoff = now - audit_retention
    if entry.created_at < cutoff or entry.id in seen_entries:
        return
    if now >= next_audit_cleanup:
        next_audit_cleanup = now + audit_retention
        for entry_id, timestamp in list(seen_entries.items()):
            if timestamp < cutoff:
                del seen_entries[entry_id]
        for key, timestamps in list(actions.items()):
            if max(timestamps) < cutoff:
                del actions[key]
    seen_entries[entry.id] = entry.created_at

    key = (guild.id, actor_id)
    timestamps = actions.get(key, []) + [entry.created_at]
    latest = max(timestamps)
    timestamps = [timestamp for timestamp in timestamps if latest - timestamp <= window]
    actions[key] = timestamps
    if len(timestamps) <= threshold_count or key in sanctions_in_progress:
        return

    sanctions_in_progress.add(key)
    actions.pop(key)
    try:
        await sanction(guild, actor_id, len(timestamps), action, getattr(entry.target, "id", None))
    finally:
        sanctions_in_progress.remove(key)


@bot.command()
async def ping(ctx):
    await ctx.send("Pong!")


@bot.group(invoke_without_command=True)
async def log(ctx):
    await ctx.send("Использование: `.log set #канал`")


@log.command(name="set")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def set_log_channel(ctx, channel: discord.TextChannel):
    permissions = channel.permissions_for(ctx.guild.me)
    if not (permissions.view_channel and permissions.send_messages):
        await ctx.send("Выдай боту права просмотра и отправки сообщений в выбранном канале.")
        return

    temporary_path = None
    try:
        with config_path.open(encoding="utf-8") as file:
            updated = json.load(file)
        channels = updated.setdefault("LOG_CHANNEL_IDS", {})
        channels[str(ctx.guild.id)] = channel.id
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=config_path.parent, delete=False) as file:
            temporary_path = Path(file.name)
            json.dump(updated, file, ensure_ascii=False, indent=2)
            file.write("\n")
        temporary_path.replace(config_path)
    except (OSError, json.JSONDecodeError):
        logger.exception("Не удалось сохранить канал отчётов для сервера %s", ctx.guild.id)
        await ctx.send("Не удалось сохранить канал отчётов. Подробности в журнале бота.")
        return
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    config["LOG_CHANNEL_IDS"] = channels
    await ctx.send(f"Канал отчётов установлен: {channel.mention}")


@set_log_channel.error
async def set_log_channel_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("Эта команда доступна администраторам сервера.")
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("Вызови команду на сервере.")
    elif isinstance(error, (commands.MissingRequiredArgument, commands.ChannelNotFound)):
        await ctx.send("Укажи текстовый канал: `.log set #канал`")
    else:
        raise error


if __name__ == "__main__":
    token = (os.environ.get("DISCORD_BOT_TOKEN") or config["TOKEN"]).strip()
    if not token:
        raise SystemExit("Задайте DISCORD_BOT_TOKEN или TOKEN в config.json")
    bot.run(token)

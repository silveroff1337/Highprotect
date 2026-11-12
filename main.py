import asyncio
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
bot.remove_command("help")
logger = logging.getLogger(__name__)

is_protection_enabled = {}
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


def log_channel_id(guild):
    return config.get("LOG_CHANNEL_IDS", {}).get(str(guild.id), config["LOG_CHANNEL_ID"])


def is_trusted(guild_id, user_id):
    if user_id not in whitelist:
        return False
    guild_ids = config.get("WHITELIST_GUILD_IDS", {}).get(str(user_id))
    return guild_ids is None or guild_id in guild_ids


def save_config(updated):
    temporary_path = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=config_path.parent, delete=False) as file:
            temporary_path = Path(file.name)
            json.dump(updated, file, ensure_ascii=False, indent=2)
            file.write("\n")
        temporary_path.replace(config_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


async def send_alert(guild, embed):
    channel_id = log_channel_id(guild)
    channel = guild.get_channel_or_thread(channel_id)
    if not isinstance(channel, discord.abc.Messageable):
        logger.warning("Канал отчётов %s недоступен на сервере %s", channel_id, guild.id)
        return False

    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        return True
    except discord.Forbidden:
        logger.warning("Нет прав отправить Embed в канал %s", channel_id)
    except discord.NotFound:
        logger.warning("Канал отчётов %s не найден", channel_id)
    except discord.HTTPException:
        logger.exception("Ошибка отправки отчёта в канал %s", channel_id)
    return False


async def remove_roles(guild, actor_id, member, reason):
    try:
        if member is None:
            member = await guild.fetch_member(actor_id)
    except discord.NotFound:
        return "участник покинул сервер"
    except discord.Forbidden:
        return "Discord запретил получить участника"
    except discord.HTTPException as error:
        return f"ошибка получения участника, HTTP {error.status}"

    me = guild.me
    removed = failed = skipped = 0
    for role in member.roles:
        if not is_protection_enabled.get(guild.id, True) or is_trusted(guild.id, actor_id):
            break
        if role.is_default():
            continue
        if role.managed or me is None or role >= me.top_role:
            skipped += 1
            continue
        try:
            await member.remove_roles(role, reason=reason)
            removed += 1
        except discord.NotFound:
            failed += 1
        except discord.Forbidden:
            failed += 1
            logger.warning("Нет прав снять роль %s у %s", role.id, actor_id)
        except discord.HTTPException:
            failed += 1
            logger.exception("Ошибка снятия роли %s у %s", role.id, actor_id)
    return f"снято {removed}, ошибок {failed}, недоступных ролей {skipped}"


async def sanction(guild, actor_id, count, action, target_id):
    if is_trusted(guild.id, actor_id):
        return
    reason = f"Anti-Nuke: {count} действий за {config['THRESHOLD_SECONDS']} с"
    member = guild.get_member(actor_id)
    remove_first = action == discord.AuditLogAction.ban
    role_status = await remove_roles(guild, actor_id, member, reason) if remove_first else "снято 0"
    me = guild.me
    if not is_protection_enabled.get(guild.id, True):
        ban_status = "защита отключена"
    elif is_trusted(guild.id, actor_id):
        ban_status = "пользователь добавлен в белый список"
    elif member is not None and (me is None or member.top_role >= me.top_role):
        ban_status = "недоступен по иерархии ролей"
    else:
        try:
            await guild.ban(discord.Object(id=actor_id), reason=reason, delete_message_seconds=0)
            ban_status = "выдан"
            if not remove_first:
                role_status = "участник забанен"
        except discord.NotFound:
            ban_status = "пользователь не найден"
        except discord.Forbidden:
            ban_status = "Discord отказал в доступе"
        except discord.HTTPException as error:
            ban_status = f"ошибка HTTP {error.status}"
    if not remove_first and ban_status != "выдан" and is_protection_enabled.get(guild.id, True) and not is_trusted(guild.id, actor_id):
        role_status = await remove_roles(guild, actor_id, member, reason)

    message = f"{reason}. Исполнитель: `{actor_id}`. Роли: {role_status}. Бан: {ban_status}."
    logger.warning("Сервер %s. %s", guild.id, message)

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

    await send_alert(guild, embed)


async def remove_webhook(guild, actor_id, webhook_id):
    result = "Discord не передал ID вебхука"
    if webhook_id is not None:
        try:
            webhook = await bot.fetch_webhook(webhook_id)
            if not is_protection_enabled.get(guild.id, True) or is_trusted(guild.id, actor_id):
                return
            if webhook.guild_id == guild.id:
                await webhook.delete(reason="Anti-Nuke: недоверенный создатель вебхука")
                result = "Вебхук удалён"
            else:
                result = "Сервер вебхука не совпадает с записью аудита"
        except discord.NotFound:
            result = "Вебхук уже отсутствует"
        except discord.Forbidden:
            result = "Discord отказал в доступе. Проверьте право «Управление вебхуками»"
        except discord.HTTPException as error:
            result = f"Ошибка Discord API (HTTP {error.status})"

    logger.warning("Сервер %s, исполнитель %s, вебхук %s: %s", guild.id, actor_id, webhook_id, result)
    embed = discord.Embed(title="🛡️ Anti-Nuke • Создание вебхука", description=result, color=0xFF0000)
    embed.add_field(name="Исполнитель", value=f"<@{actor_id}>")
    if webhook_id is not None:
        embed.add_field(name="ID вебхука", value=str(webhook_id))
    await send_alert(guild, embed)


@bot.event
async def on_audit_log_entry_create(entry):
    global next_audit_cleanup

    action = entry.action
    if action not in action_labels:
        return
    if action is discord.AuditLogAction.role_update and not hasattr(entry.after, "permissions"):
        return

    guild = entry.guild
    if not is_protection_enabled.get(guild.id, True):
        return
    actor_id = entry.user_id
    if actor_id is None or actor_id in (guild.owner_id, bot.user.id) or is_trusted(guild.id, actor_id):
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
    target_id = getattr(entry.target, "id", None)

    key = (guild.id, actor_id)
    timestamps = actions.get(key, []) + [entry.created_at]
    latest = max(timestamps)
    timestamps = [timestamp for timestamp in timestamps if latest - timestamp <= window]
    actions[key] = timestamps
    should_sanction = len(timestamps) > threshold_count and key not in sanctions_in_progress
    if should_sanction:
        sanctions_in_progress.add(key)
        actions.pop(key)

    try:
        if action == discord.AuditLogAction.webhook_create:
            await remove_webhook(guild, actor_id, target_id)
        if should_sanction and is_protection_enabled.get(guild.id, True):
            await sanction(guild, actor_id, len(timestamps), action, target_id)
    finally:
        if should_sanction:
            sanctions_in_progress.remove(key)


@bot.event
async def on_member_ban(guild, user):
    if not is_protection_enabled.get(guild.id, True):
        return
    received_at = discord.utils.utcnow()
    await asyncio.sleep(1)
    if not is_protection_enabled.get(guild.id, True):
        return
    tolerance = timedelta(seconds=5)
    try:
        entries = [
            entry
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.ban, after=received_at - tolerance,
                before=received_at + tolerance, limit=25,
            )
            if getattr(entry.target, "id", None) == user.id
        ]
    except (discord.Forbidden, discord.NotFound):
        logger.warning("Журнал банов недоступен на сервере %s", guild.id)
        return
    except discord.HTTPException:
        logger.exception("Ошибка получения журнала банов на сервере %s", guild.id)
        return
    if len(entries) == 1:
        await on_audit_log_entry_create(entries[0])


@bot.command()
async def ping(ctx):
    await ctx.send("Pong!")


@bot.command(name="help")
async def show_help(ctx):
    embed = discord.Embed(title="📚 Список команд", color=0x5865F2)
    embed.add_field(name="Основные", value="`.help` — список команд\n`.ping` — проверить связь с ботом", inline=False)
    embed.add_field(
        name="Настройки",
        value="`.panel` — открыть панель защиты\n`.log set #канал` — выбрать канал отчётов",
        inline=False,
    )
    embed.add_field(
        name="Управление доступом",
        value="`.trust @user` / `.untrust @user` — выдать или снять доверие\n"
              "`.whitelist` — показать белый список",
        inline=False,
    )
    embed.add_field(
        name="Утилиты",
        value="`.userinfo @user` — сведения об участнике\n"
              "`.reset @user` — сбросить счётчик нарушений\n"
              "`.test` — проверить канал отчётов",
        inline=False,
    )
    await ctx.send(embed=embed)


def panel_embed(guild):
    enabled = is_protection_enabled.get(guild.id, True)
    channel = guild.get_channel_or_thread(log_channel_id(guild))
    embed = discord.Embed(
        title="🛡️ Панель управления Anti-Nuke",
        color=0x57F287 if enabled else 0xED4245,
    )
    embed.add_field(name="Статус защиты", value="🟢 Включена" if enabled else "🔴 Выключена", inline=False)
    embed.add_field(name="Лимит действий", value=str(threshold_count))
    embed.add_field(name="Интервал", value=f"{config['THRESHOLD_SECONDS']} с")
    embed.add_field(name="Канал отчётов", value=channel.mention if channel else "Не настроен", inline=False)
    embed.set_footer(text="После перезапуска защита включится автоматически")
    return embed


class ProtectionPanel(discord.ui.View):
    def __init__(self, guild_id):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        if is_protection_enabled.get(guild_id, True):
            self.toggle.style = discord.ButtonStyle.danger

    @discord.ui.button(label="Вкл/Выкл защиту", style=discord.ButtonStyle.success)
    async def toggle(self, interaction, button):
        if interaction.guild_id != self.guild_id or not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("Переключатель доступен администраторам сервера.", ephemeral=True)
            return

        enabled = not is_protection_enabled.get(self.guild_id, True)
        is_protection_enabled[self.guild_id] = enabled
        if not enabled:
            for key in list(actions):
                if key[0] == self.guild_id:
                    del actions[key]
        button.style = discord.ButtonStyle.danger if enabled else discord.ButtonStyle.success
        try:
            await interaction.response.edit_message(embed=panel_embed(interaction.guild), view=self)
        except (discord.Forbidden, discord.NotFound):
            logger.warning("Панель защиты недоступна на сервере %s", self.guild_id)
        except discord.HTTPException:
            logger.exception("Ошибка обновления панели защиты на сервере %s", self.guild_id)


@bot.command()
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def panel(ctx):
    await ctx.send(embed=panel_embed(ctx.guild), view=ProtectionPanel(ctx.guild.id))


@panel.error
async def panel_error(ctx, error):
    if isinstance(error, (commands.MissingPermissions, commands.NoPrivateMessage)):
        await ctx.send("Панель доступна администраторам на сервере.")
    else:
        raise error


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

    try:
        with config_path.open(encoding="utf-8") as file:
            updated = json.load(file)
        channels = updated.setdefault("LOG_CHANNEL_IDS", {})
        channels[str(ctx.guild.id)] = channel.id
        save_config(updated)
    except (OSError, json.JSONDecodeError):
        logger.exception("Не удалось сохранить канал отчётов для сервера %s", ctx.guild.id)
        await ctx.send("Не удалось сохранить канал отчётов. Подробности в журнале бота.")
        return
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


async def change_trust(ctx, member, trusted):
    guild_id = ctx.guild.id
    user_key = str(member.id)
    can_remove_global = (
        not trusted
        and member.id in whitelist
        and user_key not in config.get("WHITELIST_GUILD_IDS", {})
        and await bot.is_owner(ctx.author)
    )
    try:
        with config_path.open(encoding="utf-8") as file:
            updated = json.load(file)
        user_ids = set(updated["WHITELIST_USER_IDS"])
        scopes = updated.setdefault("WHITELIST_GUILD_IDS", {})
        guild_ids = set(scopes.get(user_key, []))
        global_entry = member.id in user_ids and user_key not in scopes
        if not trusted and global_entry and not can_remove_global:
            description = "Глобальную запись может удалить владелец приложения бота."
        elif trusted and (global_entry or guild_id in guild_ids):
            description = f"{member.mention} уже в белом списке."
        elif not trusted and not global_entry and guild_id not in guild_ids:
            description = f"{member.mention} уже отсутствует в белом списке этого сервера."
        else:
            if trusted:
                guild_ids.add(guild_id)
            else:
                guild_ids.discard(guild_id)

            if guild_ids:
                user_ids.add(member.id)
                scopes[user_key] = sorted(guild_ids)
            else:
                user_ids.discard(member.id)
                scopes.pop(user_key, None)
            updated["WHITELIST_USER_IDS"] = sorted(user_ids)
            save_config(updated)
            config["WHITELIST_USER_IDS"] = updated["WHITELIST_USER_IDS"]
            config["WHITELIST_GUILD_IDS"] = scopes
            whitelist.clear()
            whitelist.update(user_ids)
            if trusted:
                actions.pop((guild_id, member.id), None)
                description = f"{member.mention} добавлен в белый список этого сервера."
            else:
                description = f"{member.mention} удалён из белого списка."
    except (OSError, json.JSONDecodeError):
        logger.exception("Не удалось сохранить белый список сервера %s", guild_id)
        description = "Не удалось обновить белый список. Подробности в журнале бота."

    embed = discord.Embed(title="Белый список", description=description, color=0x5865F2)
    await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())


@bot.command()
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def trust(ctx, member: discord.Member):
    await change_trust(ctx, member, True)


@bot.command()
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def untrust(ctx, member: discord.Member):
    await change_trust(ctx, member, False)


@bot.command(name="whitelist")
@commands.guild_only()
async def show_whitelist(ctx):
    entries = [
        f"<@{user_id}> · `{user_id}`" if ctx.guild.get_member(user_id) else f"`{user_id}`"
        for user_id in sorted(whitelist)
        if is_trusted(ctx.guild.id, user_id)
    ]
    for page in discord.utils.as_chunks(entries or ["Список пуст"], 50):
        embed = discord.Embed(title="Белый список", description="\n".join(page), color=0x5865F2)
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())


@bot.command()
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def reset(ctx, member: discord.Member):
    actions.pop((ctx.guild.id, member.id), None)
    embed = discord.Embed(
        title="Сброс счётчика",
        description=f"Счетчик нарушений для {member.mention} сброшен",
        color=0x57F287,
    )
    await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())


@bot.command()
@commands.guild_only()
async def userinfo(ctx, member: discord.Member):
    roles = [role.mention for role in reversed(member.roles) if not role.is_default()]
    for page in discord.utils.as_chunks(roles or ["Нет ролей"], 100):
        embed = discord.Embed(title="Информация о пользователе", color=0x5865F2)
        embed.add_field(name="Ник", value=member.display_name)
        embed.add_field(name="ID", value=str(member.id))
        embed.add_field(name="Аккаунт создан", value=discord.utils.format_dt(member.created_at, "D"), inline=False)
        embed.description = "**Роли на сервере**\n" + " ".join(page)
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())


@bot.command()
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def test(ctx):
    embed = discord.Embed(
        title="⚠️ ТЕСТОВОЕ СРАБАТЫВАНИЕ ANTI-NUKE.",
        description="Если вы это видите, логи работают",
        color=0xFEE75C,
    )
    delivered = await send_alert(ctx.guild, embed)
    result = "Тестовый отчёт доставлен." if delivered else "Тестовый отчёт не доставлен. Проверьте канал и права бота."
    await ctx.send(embed=discord.Embed(description=result, color=0x5865F2))


@trust.error
@untrust.error
@show_whitelist.error
@reset.error
@userinfo.error
@test.error
async def utility_command_error(ctx, error):
    original = getattr(error, "original", error)
    if isinstance(error, commands.MissingRequiredArgument):
        message = f"Укажите участника: `.{ctx.command.qualified_name} @user`."
    elif isinstance(error, commands.MemberNotFound):
        message = "Участник не найден на этом сервере."
    elif isinstance(error, commands.MissingPermissions):
        message = "Команда доступна администраторам сервера."
    elif isinstance(error, commands.NoPrivateMessage):
        message = "Вызовите команду в текстовом канале сервера."
    elif isinstance(original, discord.NotFound):
        message = "Участник или канал уже недоступен."
    elif isinstance(original, discord.HTTPException):
        logger.warning("Discord отклонил команду %s: HTTP %s", ctx.command, original.status)
        message = "Discord не смог выполнить команду. Проверьте доступ бота к каналу."
    else:
        raise error
    try:
        await ctx.send(embed=discord.Embed(description=message, color=0xED4245))
    except discord.HTTPException:
        logger.warning("Не удалось отправить сообщение об ошибке команды %s", ctx.command)


if __name__ == "__main__":
    token = (os.environ.get("DISCORD_BOT_TOKEN") or config["TOKEN"]).strip()
    if not token:
        raise SystemExit("Задайте DISCORD_BOT_TOKEN или TOKEN в config.json")
    bot.run(token)

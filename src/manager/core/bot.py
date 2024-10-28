import asyncio
import json
import os.path
from collections import defaultdict

from loguru import logger
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, CallbackContext


class Bot:
    def __init__(self, manager, config):
        self.run = True
        self.loop = asyncio.new_event_loop()
        self.manager = manager
        self.config = config
        self.bot = Application.builder().token(config.telegram['token']).build()
        self.bot.add_handler(MessageHandler(filters.COMMAND, self.parse_commands))
        self.bot.add_handler(MessageHandler(filters.TEXT, self.parse_messages))
        self.admin_list = config.telegram['admin_list']
        self.state = defaultdict(lambda: 0)
        asyncio.set_event_loop(self.loop)
        manager.callbacks.append(self.manager_callback)

    async def parse_commands(self, update: Update, context: CallbackContext):
        chat_id = update.message.chat_id
        text = update.message.text
        is_admin = chat_id in self.admin_list
        logger.info(f"Command received: {text}; from id: {chat_id} ({'admin' if is_admin else 'not-admin'})")
        if not is_admin:
            await update.message.reply_text(self.config.strings["not_admin"])
        state = self.state[chat_id]
        match text:
            case "/start":
                self.state[chat_id] = 1
                await update.message.reply_text(self.config.strings["start"])
            case "/help":
                await update.message.reply_text(self.config.strings["help"])
            case "/status":
                await update.message.reply_text(self.config.strings["status"])
            case "/counters":
                await update.message.reply_text(self.config.strings["counters"])
            case "/about":
                await update.message.reply_text(self.config.strings["about"])

    async def parse_messages(self, update: Update, context: CallbackContext):
        is_admin = update.message.chat_id in self.admin_list
        logger.info(f"Command received: {update.message.text}; from id: {update.message.chat_id} ({'admin' if is_admin else 'not-admin'})")

    def manager_callback(self, data_from, data_body):
        logger.info(f"{data_from, data_body}")

    def start(self):
        # load state
        if os.path.exists('state.json'):
            with open('state.json', 'r') as f:
                self.state = json.load(f)
            logger.success("[bot] State loaded")
        # Start the manager
        logger.success(f"[bot] Listening on @{self.loop.run_until_complete(self.bot.bot.get_me()).username}")
        self.bot.run_polling()


    def stop(self):
        self.run = False
        self.bot.stop_running()
        logger.success("[bot] Stopped")
        # Stop the manager
        # await application.stop()

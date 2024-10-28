from loguru import logger

from core import Config, Manager, Bot

if __name__ == '__main__':
    config = Config("./config")
    config.load()
    manager = Manager(config.manager['socket'])
    bot = Bot(manager, config)
    try:
        manager.start()
        bot.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(e)
    finally:
        bot.stop()
        manager.stop()

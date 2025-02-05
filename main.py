"""
SOLANA TRADING BOT v1.0
Author: Sheron987
Date: [Current Date]
Description: Automated trading bot with Rugcheck integration, Telegram alerts, and security checks
"""

import os
import yaml
import aiohttp
import asyncio
import logging
from datetime import datetime
from telegram import Bot, Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load configuration files
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
BLACKLIST_PATH = os.path.join(os.path.dirname(__file__), 'blacklist.yaml')

class DexScreenerAPI:
    """Handles interactions with DexScreener API"""
    
    def __init__(self):
        self.base_url = "https://api.dexscreener.com/latest/dex"
        self.headers = {"Accept": "application/json"}
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def get_pair_details(self, pair_address: str) -> dict:
        """Fetch detailed pair information from DexScreener"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/pairs/solana/{pair_address}",
                    headers=self.headers
                ) as response:
                    return await response.json()
        except Exception as e:
            logger.error(f"DexScreener API error: {str(e)}")
            return {}

class RugCheckAPI:
    """Handles interactions with Rugcheck.xyz API"""
    
    def __init__(self):
        self.base_url = "https://api.rugcheck.xyz/api/v1"
        self.headers = {"Accept": "application/json"}
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def get_token_score(self, pair_address: str) -> dict:
        """Get security score for a token"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    f"{self.base_url}/address/{pair_address}/score",
                    headers=self.headers
                ) as response:
                    return await response.json()
        except Exception as e:
            logger.error(f"Rugcheck API error: {str(e)}")
            return {}

class SecurityAnalyzer:
    """Performs comprehensive security checks"""
    
    def __init__(self):
        self.dex_screener = DexScreenerAPI()
        self.rugcheck = RugCheckAPI()
        with open(BLACKLIST_PATH) as f:
            self.blacklist = yaml.safe_load(f)
        with open(CONFIG_PATH) as f:
            self.config = yaml.safe_load(f)

    async def is_token_safe(self, pair_address: str) -> bool:
        """Run full security validation for a token"""
        # Check blacklists
        if self._is_blacklisted(pair_address):
            return False

        # Get external data
        rugcheck_data = await self.rugcheck.get_token_score(pair_address)
        dex_data = await self.dex_screener.get_pair_details(pair_address)

        # Validate all criteria
        return all([
            self._validate_rugcheck(rugcheck_data),
            self._validate_dexscreener(dex_data),
            self._validate_contract_properties(rugcheck_data)
        ])

    def _is_blacklisted(self, address: str) -> bool:
        """Check against multiple blacklist categories"""
        return any([
            address in self.blacklist['tokens'],
            any(dev in self.blacklist['developers'] for dev in self._get_associated_devs(address)),
            any(pattern in self.blacklist['malicious_patterns'] for pattern in self._detect_patterns(address))
        ])

    def _validate_rugcheck(self, data: dict) -> bool:
        """Validate Rugcheck security criteria"""
        return all([
            data.get('riskScore', 100) < self.config['security']['max_risk_score'],
            not data.get('isMintable', True),
            not data.get('isFreezable', True),
            data.get('liquidityLockScore', 0) > self.config['security']['min_liquidity_lock'],
            data.get('holdersDistributionScore', 0) > self.config['security']['min_distribution_score']
        ])

    def _validate_dexscreener(self, data: dict) -> bool:
        """Validate Dexscreener trading criteria"""
        liquidity = data.get('liquidity', {}).get('usd', 0)
        volume = data.get('volume', {}).get('h24', 0)
        return all([
            liquidity > self.config['filters']['min_liquidity'],
            (volume / liquidity if liquidity > 0 else 0) < self.config['filters']['max_volume_ratio'],
            data.get('txns', {}).get('h24', {}).get('buys', 0) > 
            data.get('txns', {}).get('h24', {}).get('sells', 0) * self.config['filters']['buy_sell_ratio']
        ])

    def _validate_contract_properties(self, data: dict) -> bool:
        """Check contract-specific properties"""
        return all([
            not data.get('isProxy', False),
            data.get('ownerBurn', False),
            data.get('verified', False)
        ])

class TradingBot:
    """Main trading bot class with Telegram integration"""
    
    def __init__(self):
        with open(CONFIG_PATH) as f:
            self.config = yaml.safe_load(f)
        self.security = SecurityAnalyzer()
        self.tg_bot = Application.builder().token(self.config['telegram']['bot_token']).build()
        self._register_handlers()
        self.positions = {}  # Track active positions
        
    def _register_handlers(self):
        """Set up Telegram command handlers"""
        self.tg_bot.add_handler(CommandHandler("start", self._cmd_start))
        self.tg_bot.add_handler(CommandHandler("watch", self._cmd_watch))
        self.tg_bot.add_handler(CommandHandler("positions", self._cmd_positions))
        self.tg_bot.add_handler(CommandHandler("stop_loss", self._cmd_stop_loss))

    # Add missing handler methods
    async def _cmd_positions(self, update: Update, context) -> None:
        """Handle /positions command"""
        if not self.positions:
            await update.message.reply_text("No active positions")
            return
            
        position_list = "\n".join(
            [f"{token}: {details['amount']} @ ${details['entry_price']}" 
             for token, details in self.positions.items()]
        )
        await update.message.reply_text(
            f"📊 Active Positions:\n{position_list}"
        )

    async def _cmd_stop_loss(self, update: Update, context) -> None:
        """Handle /stop_loss command"""
        if len(context.args) != 1:
            await update.message.reply_text("Usage: /stop_loss [percentage]")
            return
            
        try:
            new_sl = float(context.args[0])
            if not -100 < new_sl < 0:
                raise ValueError
            self.config['trading']['stop_loss'] = new_sl
            await update.message.reply_text(f"✅ Stop loss updated to {new_sl}%")
        except (ValueError, TypeError):
            await update.message.reply_text("❌ Invalid stop loss percentage")

    async def monitor_markets(self):
        """Main monitoring loop"""
        logger.info("Starting market monitoring")
        while True:
            try:
                # Add your market monitoring logic here
                await asyncio.sleep(self.config['polling_interval'])
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
                await asyncio.sleep(60)

async def main():
    """Initialize and start the bot"""
    try:
        bot = TradingBot()
        await bot.tg_bot.initialize()
        await bot.tg_bot.start()
        await bot.monitor_markets()
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
    finally:
        if 'tg_bot' in locals():
            await bot.tg_bot.stop()

if __name__ == "__main__":
    asyncio.run(main())

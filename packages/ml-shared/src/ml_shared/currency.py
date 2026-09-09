"""
ml_shared.currency

Regional currency conversion, formatting, and pricing distribution engine.
Provides region-centric localization (e.g. RUB in Russia, INR in India,
USD in USA, EUR in Europe, GBP in UK, JPY in Japan).
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class CurrencyInfo(BaseModel):
    code: str
    symbol: str
    name: str
    symbol_prefix: bool = True  # True: $49, False: 4,500 ₽
    decimals: int = 2
    # Reference exchange rate relative to 1 USD
    # Used for baseline conversions across marketplace regions
    usd_rate: float


# Supported currencies with symbols and default USD parity rates
CURRENCIES: Dict[str, CurrencyInfo] = {
    "USD": CurrencyInfo(code="USD", symbol="$", name="US Dollar", symbol_prefix=True, decimals=2, usd_rate=1.0),
    "EUR": CurrencyInfo(code="EUR", symbol="€", name="Euro", symbol_prefix=False, decimals=2, usd_rate=0.92),
    "GBP": CurrencyInfo(code="GBP", symbol="£", name="British Pound", symbol_prefix=True, decimals=2, usd_rate=0.79),
    "INR": CurrencyInfo(code="INR", symbol="₹", name="Indian Rupee", symbol_prefix=True, decimals=2, usd_rate=83.5),
    "RUB": CurrencyInfo(code="RUB", symbol="₽", name="Russian Ruble", symbol_prefix=False, decimals=0, usd_rate=92.0),
    "JPY": CurrencyInfo(code="JPY", symbol="¥", name="Japanese Yen", symbol_prefix=True, decimals=0, usd_rate=155.0),
    "CAD": CurrencyInfo(code="CAD", symbol="CA$", name="Canadian Dollar", symbol_prefix=True, decimals=2, usd_rate=1.36),
    "AUD": CurrencyInfo(code="AUD", symbol="A$", name="Australian Dollar", symbol_prefix=True, decimals=2, usd_rate=1.52),
}

# ISO 3166-1 alpha-2 region mapping to standard local currency
REGION_TO_CURRENCY: Dict[str, str] = {
    "US": "USD",
    "USA": "USD",
    "IN": "INR",
    "IND": "INR",
    "RU": "RUB",
    "RUS": "RUB",
    "GB": "GBP",
    "UK": "GBP",
    "DE": "EUR",
    "FR": "EUR",
    "IT": "EUR",
    "ES": "EUR",
    "NL": "EUR",
    "EU": "EUR",
    "JP": "JPY",
    "JPN": "JPY",
    "CA": "CAD",
    "AU": "AUD",
}


def resolve_currency(currency: Optional[str] = None, region: Optional[str] = None) -> str:
    """
    Resolves currency code from explicit currency or region identifier.
    Defaults to USD if unmapped.
    """
    if currency:
        curr_upper = currency.upper().strip()
        if curr_upper in CURRENCIES:
            return curr_upper
    if region:
        reg_upper = region.upper().strip()
        if reg_upper in REGION_TO_CURRENCY:
            return REGION_TO_CURRENCY[reg_upper]
    return "USD"


def convert_cents_to_currency(cents: int, target_currency: str) -> float:
    """
    Converts USD cents to target currency amount.
    """
    curr = CURRENCIES.get(target_currency, CURRENCIES["USD"])
    usd_amount = cents / 100.0
    return usd_amount * curr.usd_rate


def format_money(amount_or_cents: float, currency: str = "USD", is_cents: bool = False) -> str:
    """
    Formats a numeric amount with the localized currency symbol and rules.
    """
    curr = CURRENCIES.get(currency.upper(), CURRENCIES["USD"])
    val = (amount_or_cents / 100.0) if is_cents else amount_or_cents

    if curr.decimals == 0:
        formatted_num = f"{int(round(val)):,}"
    else:
        formatted_num = f"{val:,.2f}"

    if curr.symbol_prefix:
        return f"{curr.symbol}{formatted_num}"
    else:
        return f"{formatted_num} {curr.symbol}"


class LocalizedPriceGuidance(BaseModel):
    """Region-aware price guidance range and distribution."""
    currency: str
    currency_symbol: str
    region: Optional[str] = None
    min_price: float
    median_price: float
    max_price: float
    min_price_formatted: str
    median_price_formatted: str
    max_price_formatted: str
    recommended_range: str
    # Base canonical USD cents for platform persistence/comparison
    base_min_cents: int
    base_median_cents: int
    base_max_cents: int


def calculate_price_guidance(
    prices_cents: List[int],
    currency: str = "USD",
    region: Optional[str] = None,
) -> Optional[LocalizedPriceGuidance]:
    """
    Calculates localized price distribution from comparable listing prices (cents).
    Returns None if prices list is empty.
    """
    if not prices_cents:
        return None

    sorted_prices = sorted(prices_cents)
    n = len(sorted_prices)

    min_cents = sorted_prices[0]
    max_cents = sorted_prices[-1]

    if n % 2 == 1:
        median_cents = sorted_prices[n // 2]
    else:
        median_cents = int(round((sorted_prices[n // 2 - 1] + sorted_prices[n // 2]) / 2))

    curr_info = CURRENCIES.get(currency.upper(), CURRENCIES["USD"])

    min_local = convert_cents_to_currency(min_cents, curr_info.code)
    med_local = convert_cents_to_currency(median_cents, curr_info.code)
    max_local = convert_cents_to_currency(max_cents, curr_info.code)

    min_fmt = format_money(min_local, curr_info.code)
    med_fmt = format_money(med_local, curr_info.code)
    max_fmt = format_money(max_local, curr_info.code)

    recommended_range = f"{min_fmt} - {max_fmt}"

    return LocalizedPriceGuidance(
        currency=curr_info.code,
        currency_symbol=curr_info.symbol,
        region=region,
        min_price=round(min_local, 2 if curr_info.decimals > 0 else 0),
        median_price=round(med_local, 2 if curr_info.decimals > 0 else 0),
        max_price=round(max_local, 2 if curr_info.decimals > 0 else 0),
        min_price_formatted=min_fmt,
        median_price_formatted=med_fmt,
        max_price_formatted=max_fmt,
        recommended_range=recommended_range,
        base_min_cents=min_cents,
        base_median_cents=median_cents,
        base_max_cents=max_cents,
    )

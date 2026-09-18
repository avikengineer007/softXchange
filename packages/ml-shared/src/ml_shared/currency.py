"""
ml_shared.currency

Currency formatting and pricing distribution engine standardized strictly on
the Indian Rupee (INR / ₹). All foreign currency exchange mechanisms have
been retired in favor of single canonical INR accounting.

Note on `_cents` fields:
All database and API fields named `*_cents` (e.g. `price_cents`, `amount_cents`,
`base_min_cents`) represent integer minor currency units (paise, where
1 INR = 100 paise). The field names are deliberately retained to avoid breaking
persisted database schemas and client contracts.
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class CurrencyInfo(BaseModel):
    code: str
    symbol: str
    name: str
    symbol_prefix: bool = True  # e.g. ₹49.00
    decimals: int = 2
    # Parity baseline: 1.0 (INR is the platform canonical currency)
    usd_rate: float = 1.0


DEFAULT_CURRENCY: str = "INR"

# Sole supported platform currency: Indian Rupee (INR / ₹)
CURRENCIES: Dict[str, CurrencyInfo] = {
    "INR": CurrencyInfo(
        code="INR",
        symbol="₹",
        name="Indian Rupee",
        symbol_prefix=True,
        decimals=2,
        usd_rate=1.0,
    ),
}

# Regional mapping resolves exclusively to INR
REGION_TO_CURRENCY: Dict[str, str] = {
    "IN": "INR",
    "IND": "INR",
}


def resolve_currency(currency: Optional[str] = None, region: Optional[str] = None) -> str:
    """
    Resolves currency code. The platform operates exclusively in Indian Rupee (INR).
    Always returns "INR".
    """
    return DEFAULT_CURRENCY


def convert_cents_to_currency(cents: int, target_currency: str = "INR") -> float:
    """
    Converts minor units (paise, 100 paise = 1 INR) to INR major amount.
    `cents` represents minor units (paise).
    """
    return cents / 100.0


def format_money(amount_or_cents: float, currency: str = "INR", is_cents: bool = False) -> str:
    """
    Formats a numeric amount with the Indian Rupee symbol (₹).
    If is_cents=True, amount_or_cents is treated as minor units (paise).
    """
    curr = CURRENCIES["INR"]
    val = (amount_or_cents / 100.0) if is_cents else amount_or_cents

    formatted_num = f"{val:,.2f}"
    return f"{curr.symbol}{formatted_num}"


class LocalizedPriceGuidance(BaseModel):
    """INR price guidance range and distribution."""
    currency: str = "INR"
    currency_symbol: str = "₹"
    region: Optional[str] = "IN"
    min_price: float
    median_price: float
    max_price: float
    min_price_formatted: str
    median_price_formatted: str
    max_price_formatted: str
    recommended_range: str
    # Base canonical minor units (paise: 1 INR = 100 paise) for persistence/comparison
    base_min_cents: int
    base_median_cents: int
    base_max_cents: int


def calculate_price_guidance(
    prices_cents: List[int],
    currency: str = "INR",
    region: Optional[str] = None,
) -> Optional[LocalizedPriceGuidance]:
    """
    Calculates localized INR price distribution from comparable listing prices (paise).
    Returns None if prices list is empty.
    Note: prices_cents values represent integer minor units (paise).
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
        median_cents = round((sorted_prices[n // 2 - 1] + sorted_prices[n // 2]) / 2)

    curr_info = CURRENCIES["INR"]

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
        region=region or "IN",
        min_price=round(min_local, 2),
        median_price=round(med_local, 2),
        max_price=round(max_local, 2),
        min_price_formatted=min_fmt,
        median_price_formatted=med_fmt,
        max_price_formatted=max_fmt,
        recommended_range=recommended_range,
        base_min_cents=min_cents,
        base_median_cents=median_cents,
        base_max_cents=max_cents,
    )

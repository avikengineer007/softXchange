"""
Unit tests for ml_shared.currency.
Tests regional currency resolution, conversions, formatting, and pricing distribution.
"""

import pytest
from ml_shared.currency import (
    resolve_currency,
    convert_cents_to_currency,
    format_money,
    calculate_price_guidance,
    CURRENCIES,
)


def test_resolve_currency_by_code_and_region():
    assert resolve_currency("USD") == "USD"
    assert resolve_currency("rub") == "RUB"
    assert resolve_currency("inr") == "INR"
    assert resolve_currency("eur") == "EUR"
    assert resolve_currency("gbp") == "GBP"
    assert resolve_currency("jpy") == "JPY"

    # Region code fallback
    assert resolve_currency(region="RU") == "RUB"
    assert resolve_currency(region="IN") == "INR"
    assert resolve_currency(region="US") == "USD"
    assert resolve_currency(region="GB") == "GBP"
    assert resolve_currency(region="EU") == "EUR"
    assert resolve_currency(region="JP") == "JPY"

    # Unknown defaults to USD
    assert resolve_currency(region="ZZ") == "USD"
    assert resolve_currency(None, None) == "USD"


def test_format_money_across_regions():
    # USD: $49.00
    assert format_money(4900, "USD", is_cents=True) == "$49.00"

    # INR: ₹4,091.50
    inr_val = 4091.5
    assert format_money(inr_val, "INR") == "₹4,091.50"

    # RUB: 4,508 ₽ (no decimals)
    assert format_money(4508.0, "RUB") == "4,508 ₽"

    # EUR: 45.08 €
    assert format_money(45.08, "EUR") == "45.08 €"

    # GBP: £38.71
    assert format_money(38.71, "GBP") == "£38.71"

    # JPY: ¥7,595
    assert format_money(7595.0, "JPY") == "¥7,595"


def test_calculate_price_guidance_distributions():
    # Prices in USD cents: $39.00 (3900), $59.00 (5900), $89.00 (8900)
    prices = [3900, 5900, 8900]

    # USD
    guidance_usd = calculate_price_guidance(prices, currency="USD", region="US")
    assert guidance_usd is not None
    assert guidance_usd.currency == "USD"
    assert guidance_usd.base_min_cents == 3900
    assert guidance_usd.base_median_cents == 5900
    assert guidance_usd.base_max_cents == 8900
    assert guidance_usd.recommended_range == "$39.00 - $89.00"

    # Russian Ruble (RUB)
    guidance_rub = calculate_price_guidance(prices, currency="RUB", region="RU")
    assert guidance_rub is not None
    assert guidance_rub.currency == "RUB"
    assert guidance_rub.currency_symbol == "₽"
    # 39 * 92 = 3588, 89 * 92 = 8188
    assert "₽" in guidance_rub.recommended_range
    assert guidance_rub.min_price == 3588

    # Indian Rupee (INR)
    guidance_inr = calculate_price_guidance(prices, currency="INR", region="IN")
    assert guidance_inr is not None
    assert guidance_inr.currency == "INR"
    assert guidance_inr.currency_symbol == "₹"
    assert "₹" in guidance_inr.recommended_range


def test_calculate_price_guidance_empty_list():
    assert calculate_price_guidance([]) is None

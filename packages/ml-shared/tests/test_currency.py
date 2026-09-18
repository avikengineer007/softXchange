"""
Unit tests for ml_shared.currency.
Tests single canonical Indian Rupee (INR / ₹) resolution, formatting, and pricing distribution.
"""

import pytest
from ml_shared.currency import (
    resolve_currency,
    convert_cents_to_currency,
    format_money,
    calculate_price_guidance,
    CURRENCIES,
    DEFAULT_CURRENCY,
)


def test_resolve_currency_always_returns_inr():
    # Explicit inputs all resolve to INR
    assert resolve_currency("INR") == "INR"
    assert resolve_currency("inr") == "INR"
    assert resolve_currency("USD") == "INR"
    assert resolve_currency("EUR") == "INR"
    assert resolve_currency("RUB") == "INR"

    # Region code fallback always resolves to INR
    assert resolve_currency(region="IN") == "INR"
    assert resolve_currency(region="US") == "INR"
    assert resolve_currency(region="RU") == "INR"
    assert resolve_currency(region="ZZ") == "INR"
    assert resolve_currency(None, None) == "INR"
    assert DEFAULT_CURRENCY == "INR"


def test_format_money_inr_only():
    # 4900 paise -> ₹49.00
    assert format_money(4900, is_cents=True) == "₹49.00"
    assert format_money(4900, "INR", is_cents=True) == "₹49.00"

    # Large amount with comma formatting: ₹4,091.50
    inr_val = 4091.5
    assert format_money(inr_val) == "₹4,091.50"
    assert format_money(inr_val, "INR") == "₹4,091.50"


def test_convert_cents_to_currency_minor_units():
    # 100 paise = 1.00 INR
    assert convert_cents_to_currency(100) == 1.0
    assert convert_cents_to_currency(4900) == 49.0
    assert convert_cents_to_currency(250000) == 2500.0


def test_calculate_price_guidance_distributions():
    # Prices in paise: ₹39.00 (3900), ₹59.00 (5900), ₹89.00 (8900)
    prices = [3900, 5900, 8900]

    guidance = calculate_price_guidance(prices)
    assert guidance is not None
    assert guidance.currency == "INR"
    assert guidance.currency_symbol == "₹"
    assert guidance.base_min_cents == 3900
    assert guidance.base_median_cents == 5900
    assert guidance.base_max_cents == 8900
    assert guidance.min_price == 39.00
    assert guidance.median_price == 59.00
    assert guidance.max_price == 89.00
    assert guidance.recommended_range == "₹39.00 - ₹89.00"


def test_calculate_price_guidance_empty_list():
    assert calculate_price_guidance([]) is None


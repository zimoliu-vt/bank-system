from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import threading
import time

import requests


RATE_CACHE = {}
RATE_CACHE_SECONDS = 15 * 60
RATE_CACHE_LOCK = threading.Lock()


class ExchangeError(Exception):
    pass


def get_rates(base_currency, quote_currencies):
    base = str(base_currency or "").strip().upper()
    quotes = tuple(sorted({str(currency).strip().upper() for currency in quote_currencies if str(currency).strip().upper() != base}))
    if not quotes:
        return {}, None
    cache_key = (base, quotes)
    with RATE_CACHE_LOCK:
        cached = RATE_CACHE.get(cache_key)
        if cached and time.monotonic() - cached[0] < RATE_CACHE_SECONDS:
            return cached[1], cached[2]
    try:
        response = requests.get("https://api.frankfurter.dev/v2/rates", params={"base": base.lower(), "quotes": ",".join(currency.lower() for currency in quotes)}, timeout=6)
        response.raise_for_status()
        rows = response.json()
        rates = {str(row["quote"]).upper(): Decimal(str(row["rate"])) for row in rows}
        if any(currency not in rates for currency in quotes):
            raise KeyError("Missing requested currency")
        rate_date = max((str(row.get("date", "")) for row in rows), default="") or None
    except (requests.RequestException, KeyError, TypeError, ValueError, InvalidOperation) as error:
        raise ExchangeError("Could not retrieve exchange rates") from error
    with RATE_CACHE_LOCK:
        RATE_CACHE[cache_key] = (time.monotonic(), rates, rate_date)
    return rates, rate_date


def get_total_value(balances, base_currency):
    base = str(base_currency or "").strip().upper()
    amounts = {str(currency).upper(): Decimal(str(amount)) for currency, amount in balances.items()}
    foreign_currencies = [currency for currency, amount in amounts.items() if currency != base and amount != 0]
    rates, rate_date = get_rates(base, foreign_currencies)
    total = amounts.get(base, Decimal("0"))
    for currency in foreign_currencies:
        total += amounts[currency] / rates[currency]
    total = total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {"currency": base, "amount": f"{total:.2f}", "rate_date": rate_date, "complete": True}


def get_quote(from_currency, to_currency, amount):
    source = str(from_currency or "").strip().upper()
    target = str(to_currency or "").strip().upper()
    if source == target:
        raise ExchangeError("Choose two different currencies")
    try:
        amount_value = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError, ValueError) as error:
        raise ExchangeError("Amount must be a valid number") from error
    if amount_value <= 0:
        raise ExchangeError("Amount must be greater than zero")
    rates, rate_date = get_rates(source, [target])
    rate = rates[target]
    converted = (amount_value * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {"from_currency": source, "to_currency": target, "amount": f"{amount_value:.2f}", "converted_amount": f"{converted:.2f}", "rate": str(rate), "date": rate_date, "provider": "Frankfurter reference rates"}

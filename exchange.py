from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import requests


class ExchangeError(Exception):
    pass


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
    try:
        response = requests.get(f"https://api.frankfurter.dev/v2/rate/{source.lower()}/{target.lower()}", timeout=10)
        response.raise_for_status()
        data = response.json()
        rate = Decimal(str(data["rate"]))
    except (requests.RequestException, KeyError, ValueError, InvalidOperation) as error:
        raise ExchangeError("Could not retrieve an exchange rate") from error
    converted = (amount_value * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {"from_currency": source, "to_currency": target, "amount": f"{amount_value:.2f}", "converted_amount": f"{converted:.2f}", "rate": str(rate), "date": data.get("date"), "provider": "Frankfurter reference rates"}

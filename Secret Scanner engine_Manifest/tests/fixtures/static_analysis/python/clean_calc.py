import os
import sys

def calculate_discount(price, discount_percent):
    """Calculates discounted price safely."""
    if not (0 <= discount_percent <= 100):
        raise ValueError("Invalid discount percentage")
    return price * (1.0 - (discount_percent / 100.0))

if __name__ == "__main__":
    result = calculate_discount(100.0, 15.0)
    print(f"Discounted: {result}")

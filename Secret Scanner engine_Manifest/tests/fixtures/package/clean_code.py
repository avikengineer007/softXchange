# Clean source file with standard business logic and no secrets

def calculate_invoice_total(items, tax_rate=0.05):
    subtotal = sum(item['price'] * item['quantity'] for item in items)
    tax = subtotal * tax_rate
    return subtotal + tax

def format_currency(amount):
    return f"${amount:,.2f}"

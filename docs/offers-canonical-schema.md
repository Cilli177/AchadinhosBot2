# Canonical Offer Contract

## Purpose

This contract standardizes affiliate offers before ranking, enrichment, creative generation, or publishing workflows.

## Required Shape

```json
{
  "offers": [
    {
      "source": "Shopee",
      "product_name": "Produto",
      "product_url": "https://...",
      "original_price": 199.9,
      "promo_price": 99.9,
      "discount_percent": 50,
      "store_name": "Loja XYZ",
      "category": "Eletronicos",
      "commission_raw": "10%",
      "extra_fields": {
        "raw_row": "..."
      }
    }
  ]
}
```

## Field Rules

- `source`: marketplace, platform, or origin system name.
- `product_name`: human-readable title for the offer.
- `product_url`: original or normalized destination URL.
- `original_price`: numeric value when present.
- `promo_price`: numeric value when present.
- `discount_percent`: derived when possible, otherwise null.
- `store_name`: seller or store label when available.
- `category`: product category when available.
- `commission_raw`: raw commission text or numeric payload from the source.
- `extra_fields`: any source-specific metadata that should be preserved without polluting the canonical contract.

## Normalization Rules

- Preserve unknown source fields inside `extra_fields`.
- Do not guess absent values.
- Keep numeric fields numeric when safely parseable.
- Return a summary with source, item count, and validation gaps.

# AchadinhosBot Agent Workflow

## Offer Intake Rule

Any pasted JSON, CSV export, spreadsheet-like text, or API response containing offers must be normalized before analysis, prioritization, or creative generation.

## Skill Order

1. Use `affiliate-data-loader` whenever the input comes from local files, pasted blobs, spreadsheets, or mixed sources.
2. Use `affiliate-api-fetcher` only when the user explicitly provides an API, webhook, or remote fetch path.
3. After normalization, downstream analysis can rank, enrich, or transform the resulting offers.

## Safety Rules

- Never invent missing endpoints, payload fields, or credentials.
- External API access only happens with explicit user-provided configuration and secure credentials outside source code.
- When fields are missing, keep them empty/null in the normalized payload and note the gap in the summary.

## Canonical Offer Shape

```json
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
  "extra_fields": {}
}
```

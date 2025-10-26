# Rust Actix-web + MySQL API

Endpoints (PL):

- POST /api/register — rejestracja (body: {"login","password"}) → {"token"}
- POST /api/login — logowanie (body: {"login","password"}) → {"token"}
- GET /api/products[?name=...] — lista produktów: id, name, price_cents
- GET /api/products/{id} — szczegóły produktu: id, name, price_cents, stock, details, storage, ingredients
- POST /api/orders — [AUTH Bearer] utworzenie zamówienia (adres, opcjonalny promo_code, items) → zwraca szczegóły zamówienia z id i statusem
- GET /api/orders — [AUTH] lista zamówień (id, status, created_at, total_cents, total_items)
- GET /api/orders/{id} — [AUTH] szczegóły zamówienia (jak w tworzeniu)
- POST /api/orders/{id}/cancel — [AUTH] anulowanie zamówienia (tylko gdy status=pending)
- POST /api/logout— [AUTH] wylogowanie
- POST /api/discounts/check — sprawdzenie kodu zniżkowego (body: {"code"})

## Uruchomienie (Windows PowerShell)

Wymagany Rust (cargo) oraz serwer MySQL. W katalogu `rust-api/`:

```powershell
# (ustaw adres bazy; przykład lokalnie z bazą 'angflow')
$env:MYSQL_URL = "mysql://root@127.0.0.1:3306/angflow"
# (opcjonalnie) własny sekret JWT
# $env:JWT_SECRET = "super_tajny_klucz"

cargo run
```

Serwer wystartuje domyślnie na http://127.0.0.1:8080.

## Uwagi
- Baza MySQL i tabele są tworzone automatycznie przy starcie na podstawie pliku `sql/init.sql` (seed kilku produktów + kod PROMO10). Jeśli baza z `MYSQL_URL` nie istnieje, aplikacja spróbuje ją utworzyć.
- Token JWT ważny 7 dni. Do żądań wymagających autoryzacji dodaj nagłówek: `Authorization: Bearer <token>`.

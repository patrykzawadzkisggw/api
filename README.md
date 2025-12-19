# Rust Actix-web + MySQL API — dokumentacja endpointów

W skrócie:
- Serwer: domyślnie HTTP na `0.0.0.0:8080` (można włączyć TLS przez ustawienie certyfikatów).
- Baza: MySQL — adres ustawiany przez `MYSQL_URL` lub `DATABASE_URL`.
- Autoryzacja: JWT Bearer (nagłówek `Authorization: Bearer <token>`). Token ważny 7 dni.

Formaty odpowiedzi i błędów:
- Sukces: status 200 i JSON (z wyjątkiem rejestracji/logowania które zwracają tokeny).
- Błąd walidacji: status 400 lub 400 z JSON zawierającym obiekt błędów (np. przy tworzeniu zamówienia).
- Nieautoryzowany: status 401.
- Nie znaleziono: status 404.
- Błąd serwera: status 500.

-------------------------
Endpointy
-------------------------

1) POST /api/register
- Opis: rejestracja nowego użytkownika.
- Body (JSON): {"login": string, "password": string}
	- `login` jest przycinany (trim) i nie może zawierać spacji.
	- `password` musi mieć min. 8 znaków, zawierać co najmniej jedną wielką, jedną małą literę, jedną cyfrę i co najmniej jeden znak specjalny.
- Odpowiedź 200: {"token": "<jwt>"}
- Błędy: 400 z opisem (np. "Login jest wymagany", "Hasło musi zawierać..."). Jeśli login już istnieje zwróci 400 z komunikatem o niedostępności loginu.

2) POST /api/login
- Opis: logowanie istniejącego użytkownika.
- Body (JSON): {"login": string, "password": string}
- Odpowiedź 200: {"token": "<jwt>"}
- Błędy: 400 gdy nieprawidłowe dane logowania.

3) POST /api/logout
- Opis: wylogowanie — unieważnia aktualny token (wstawiany do tabeli `revoked_tokens`).
- Nagłówek: `Authorization: Bearer <token>` (wymagane)
- Body: brak.
- Odpowiedź 200: {"status":"ok"}
- Błędy: 400/401 gdy brak lub zły token.

4) GET /api/products
- Opis: lista produktów.
- Query params opcjonalne:
	- `name` — filtruje produkty po nazwie (użycie SQL LIKE).
- Odpowiedź 200: lista obiektów ProductListItem.

Struktura ProductListItem (JSON):
{
	"id": number,
	"name": string,
	"price_cents": number,
	"stock": number,
	"price_before_cents": number | null,
	"images": [string],
	"categories": [string]
}

5) GET /api/products/{id}
- Opis: szczegóły produktu.
- Parametry ścieżki: `id` (liczba)
- Odpowiedź 200: ProductDetail

Struktura ProductDetail (JSON):
{
	"id": number,
	"name": string,
	"price_cents": number,
	"stock": number,
	"details": string,
	"storage": string,
	"ingredients": string,
	"price_before_cents": number | null,
	"images": [string],
	"categories": [string]
}

6) GET /api/products/recommended
- Opis: proste rekomendacje — zwraca do 5 produktów (LIMIT 5, domyślnie wg id).
- Odpowiedź: lista ProductListItem.

7) GET /api/products/by_ids?ids=1,2,3
- Opis: pobiera produkty po liście id. Kolejność wyników zachowuje kolejność id z parametru.
- Query params: `ids` — lista id rozdzielona przecinkami.
- Odpowiedź: lista ProductListItem (może być pusta jeśli brak id).

8) GET /api/products/search?q=fraza
- Opis: wyszukiwanie pełnotekstowe/fuzzy po `name`, `ingredients` i kategoriach.
- Query params: `q` (wymagane) — zapytanie wyszukiwawcze.
- Logika: normalizacja (lowercase + ascii transliteration), porównanie zawierania oraz dopasowanie z użyciem Damerau–Levenshtein (fuzzy). Zwraca do 100 najlepszych kandydatów.
- Odpowiedź: lista ProductListItem.

9) POST /api/discounts/check
- Opis: sprawdzenie poprawności kodu zniżkowego.
- Body (JSON): {"code": string}
- Odpowiedź 200 (gdy istnieje): {"valid": bool, "percentage": number}
- Jeśli kod nie istnieje: {"valid": false, "percentage": 0}

10) POST /api/orders  [AUTH]
- Opis: utworzenie zamówienia dla zalogowanego użytkownika.
- Nagłówek: `Authorization: Bearer <token>` (wymagane)
- Body (JSON) — CreateOrderRequest:
{
	"first_name": string,
	"last_name": string,
	"city": string,
	"postal_code": string,   // format: DD-DDD (np. "12-345")
	"address": string,
	"promo_code": string | null,
	"items": [{ "product_id": number, "quantity": number }]
}

- Walidacja:
	- Imię i nazwisko: min 2 znaki, bez cyfr.
	- Miasto: wymagane, bez cyfr.
	- Adres: min 5 znaków.
	- Kod pocztowy: format "DD-DDD".
	- Każda pozycja `quantity` musi być > 0.
- Logika cen:
	- `products_sum_cents` = suma produktów (price_cents * qty).
	- `delivery_cents` = 1500 jeśli products_sum_cents < 30000, w przeciwnym razie 0.
	- `discount_cents` = procent z `base_for_discount` (produkty + dostawa) jeśli promocja aktywna.
	- `total_cents` = base_for_discount - discount_cents.

- Odpowiedź 200 — CreateOrderResponse:
{
	"id": number,
	"status": string,           // domyślnie "W drodze"
	"created_at": string,       // RFC3339
	"total_cents": number,
	"delivery_cents": number,
	"discount_cents": number,
	"total_items": number,
	"items": [ { "product_id": number, "name": string, "quantity": number, "price_cents": number, "image": string } ],
	"first_name": string,
	"last_name": string,
	"city": string,
	"postal_code": string,
	"address": string,
	"promo_code": string | null
}

- Błędy:
	- 400 z JSON szczegółowym gdy walidacja pól nie przejdzie (z kluczem "error": "invalid_order" i mapą błędów pól).
	- 400 z listą brakujących produktów lub niewystarczającym stanem magazynowym (zawiera szczegóły shortage).

11) GET /api/orders  [AUTH]
- Opis: lista zamówień zalogowanego użytkownika.
- Odpowiedź: lista obiektów {id, status, created_at, total_cents, total_items, images}

12) GET /api/orders/{id}  [AUTH]
- Opis: szczegóły zamówienia — tylko właściciel.
- Odpowiedź: CreateOrderResponse (jak przy tworzeniu), lub 404 jeśli brak.

13) GET /api/orders/{id}/status  [AUTH]
- Opis: zwraca krótki komunikat o statusie i nazwę pliku obrazu PNG (używane np. do ilustracji statusu).
- Odpowiedź przykładowo: {"message":"...","image":"placed.png"}

14) POST /api/orders/{id}/cancel  [AUTH]
- Opis: anuluje zamówienie — tylko gdy aktualny status to "W drodze".
- Działanie: przywraca zapas produktów (zwiększa stock) i ustawia `status` = "Anulowane".
- Odpowiedź: {"status":"Anulowane"}

-------------------------
Bazy danych i inicjalizacja
-------------------------
- Plik `sql/init.sql` używany jest do utworzenia struktur tabel i zasiania przykładowych danych (produkty, kod PROMO10 itd.).
- Przy uruchomieniu aplikacja spróbuje utworzyć bazę jeśli nie istnieje (na podstawie URL z `MYSQL_URL`).

-------------------------
Zmiennne środowiskowe
-------------------------
- `MYSQL_URL` lub `DATABASE_URL` — wymagany adres połączenia z MySQL (np. `mysql://user:pass@127.0.0.1:3306/dbname`).
- `JWT_SECRET` — (opcjonalne) sekret do podpisywania tokenów JWT; jeśli nie ustawione, generowany jest losowy.
- `TLS_CERT_PATH` — ścieżka do pliku PEM z certyfikatem (fullchain). Domyślnie `/etc/letsencrypt/.../fullchain.pem`.
- `TLS_KEY_PATH` — ścieżka do klucza prywatnego PEM. Domyślnie `/etc/letsencrypt/.../privkey.pem`.
- `HOST` — host na którym ma nasłuchiwać (domyślnie `0.0.0.0`).
- `PORT` — port (domyślnie `8080`).

-------------------------
Uruchomienie (Windows PowerShell)
-------------------------
Przykład uruchomienia lokalnie z MySQL:

```powershell
# (ustaw adres bazy; przykład lokalnie z bazą 'angflow')
$env:MYSQL_URL = "mysql://root@127.0.0.1:3306/angflow"
# (opcjonalnie) własny sekret JWT
# $env:JWT_SECRET = "super_tajny_klucz"

cargo run
```

Serwer wystartuje domyślnie na http://127.0.0.1:8080.

## HTTPS (Let's Encrypt)

Aplikacja może działać po HTTPS na tym samym porcie 8080. Domyślnie szuka certyfikatu w ścieżkach:

- Certyfikat (chain): `/etc/letsencrypt/live/securebox.hopto.org/fullchain.pem`
- Klucz prywatny: `/etc/letsencrypt/live/securebox.hopto.org/privkey.pem`

Możesz je zmienić zmiennymi środowiskowymi:

```powershell
$env:TLS_CERT_PATH = "/etc/letsencrypt/live/securebox.hopto.org/fullchain.pem"
$env:TLS_KEY_PATH  = "/etc/letsencrypt/live/securebox.hopto.org/privkey.pem"
```

Jeśli pliki nie są dostępne lub niepoprawne, aplikacja automatycznie uruchomi się po HTTP na porcie 8080. Gdy certyfikaty są dostępne, serwer nasłuchuje pod adresem `https://host:8080`.


use actix_cors::Cors;
use actix_web::{dev::Payload, error::ErrorUnauthorized, get, http::header, post, web, App, Error as ActixError, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{mysql::MySqlPoolOptions, Row, MySqlPool};
use std::{env, future::Future, pin::Pin};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader};
use thiserror::Error;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
// TLS
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

#[derive(Clone)]
struct AppState {
    pool: MySqlPool,
    jwt_encoding: EncodingKey,
    jwt_decoding: DecodingKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: usize,
}

struct AuthUser(pub i64);

impl FromRequest for AuthUser {
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = req.app_data::<web::Data<AppState>>().cloned();
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .cloned();
        Box::pin(async move {
            let state = state.ok_or_else(|| ErrorUnauthorized("Missing app state"))?;
            let auth_binding = auth_header
                .ok_or_else(|| ErrorUnauthorized("Brak nagłówka Authorization"))?;
            let auth = auth_binding
                .to_str()
                .map_err(|_| ErrorUnauthorized("Nieprawidłowy nagłówek Authorization"))?;
            if !auth.starts_with("Bearer ") {
                return Err(ErrorUnauthorized("Wymagany Bearer token"));
            }
            let token = &auth[7..];
            let data = decode::<Claims>(
                token,
                &state.jwt_decoding,
                &Validation::new(Algorithm::HS256),
            )
            .map_err(|_| ErrorUnauthorized("Nieprawidłowy token"))?;
            // Sprawdź czy token nie został wylogowany (zlistowany)
            let revoked = sqlx::query("SELECT 1 FROM revoked_tokens WHERE token = ? LIMIT 1")
                .bind(token)
                .fetch_optional(&state.pool)
                .await
                .map_err(|_| ErrorUnauthorized("Błąd autoryzacji"))?;
            if revoked.is_some() {
                return Err(ErrorUnauthorized("Token został wylogowany"));
            }
            Ok(AuthUser(data.claims.sub))
        })
    }
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("Nie znaleziono")] 
    NotFound,
    #[error("Błąd walidacji: {0}")] 
    BadRequest(String),
    #[error("Błąd serwera")] 
    Server,
}

impl actix_web::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::NotFound => HttpResponse::NotFound().json(serde_json::json!({"error":"not_found"})),
            ApiError::BadRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({"error":msg})),
            ApiError::Server => HttpResponse::InternalServerError().json(serde_json::json!({"error":"server_error"})),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest { login: String, password: String }
#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse { token: String }

#[post("/api/register")]
async fn register(data: web::Data<AppState>, body: web::Json<LoginRequest>) -> Result<impl Responder, ApiError> {
    let LoginRequest { login: user_login, password } = body.into_inner();
    if user_login.trim().is_empty() {
        return Err(ApiError::BadRequest("Login jest wymagany".into()));
    }
    if let Err(msg) = validate_password(&password) {
        return Err(ApiError::BadRequest(msg));
    }
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::Server)?
        .to_string();

    let mut tx = data.pool.begin().await.map_err(|_| ApiError::Server)?;
    let res = sqlx::query("INSERT INTO users(login, password_hash) VALUES(?, ?)")
        .bind(&user_login)
        .bind(&hash)
        .execute(&mut *tx)
        .await;
    match res {
        Ok(done) => {
            let user_id = done.last_insert_id() as i64;
            tx.commit().await.map_err(|_| ApiError::Server)?;
            let token = make_jwt(user_id, &data);
            Ok(web::Json(TokenResponse { token }))
        }
        Err(e) => {
            let msg = if let sqlx::Error::Database(db) = &e { if db.message().contains("UNIQUE") { "Użytkownik już istnieje".into() } else { format!("Błąd bazy: {}", db.message()) } } else { "Błąd bazy".into() };
            Err(ApiError::BadRequest(msg))
        }
    }
}

#[post("/api/login")]
async fn login(data: web::Data<AppState>, body: web::Json<LoginRequest>) -> Result<impl Responder, ApiError> {
    let LoginRequest { login: user_login, password } = body.into_inner();
    let rec = sqlx::query("SELECT id, password_hash FROM users WHERE login = ?")
        .bind(&user_login)
        .fetch_optional(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?;
    if let Some(row) = rec {
        let id: i64 = row.get("id");
        let phash: String = row.get("password_hash");
        let parsed = PasswordHash::new(&phash).map_err(|_| ApiError::Server)?;
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        if ok {
            let token = make_jwt(id, &data);
            return Ok(web::Json(TokenResponse{ token }));
        }
    }
    Err(ApiError::BadRequest("Nieprawidłowy login lub hasło".into()))
}

#[post("/api/logout")]
async fn logout(data: web::Data<AppState>, req: HttpRequest, _user: AuthUser) -> Result<impl Responder, ApiError> {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::BadRequest("Brak nagłówka Authorization".into()))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("Nieprawidłowy nagłówek Authorization".into()))?;
    if !auth.starts_with("Bearer ") {
        return Err(ApiError::BadRequest("Wymagany Bearer token".into()));
    }
    let token = &auth[7..];
    let data_claims = decode::<Claims>(token, &data.jwt_decoding, &Validation::new(Algorithm::HS256))
        .map_err(|_| ApiError::BadRequest("Nieprawidłowy token".into()))?;
    let exp = data_claims.claims.exp as i64;
    sqlx::query("INSERT IGNORE INTO revoked_tokens(token, exp) VALUES(?, ?)")
        .bind(token)
        .bind(exp)
        .execute(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?;
    Ok(web::Json(serde_json::json!({"status":"ok"})))
}

fn make_jwt(user_id: i64, data: &web::Data<AppState>) -> String {
    let exp = (Utc::now() + chrono::Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user_id, exp };
    encode(&Header::new(Algorithm::HS256), &claims, &data.jwt_encoding).unwrap()
}

fn validate_password(pwd: &str) -> Result<(), String> {
    if pwd.len() < 8 { return Err("Hasło musi mieć co najmniej 8 znaków".into()); }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;
    for ch in pwd.chars() {
        if ch.is_ascii_uppercase() { has_upper = true; }
        else if ch.is_ascii_lowercase() { has_lower = true; }
        else if ch.is_ascii_digit() { has_digit = true; }
        else if ch.is_ascii_punctuation() || (!ch.is_alphanumeric() && ch.is_ascii()) { has_special = true; }
        else if !ch.is_ascii() { has_special = true; }
    }
    if !has_upper { return Err("Hasło musi zawierać co najmniej jedną wielką literę".into()); }
    if !has_lower { return Err("Hasło musi zawierać co najmniej jedną małą literę".into()); }
    if !has_digit { return Err("Hasło musi zawierać co najmniej jedną cyfrę".into()); }
    if !has_special { return Err("Hasło musi zawierać co najmniej jeden znak specjalny".into()); }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ProductListItem { id: i64, name: String, price_cents: i64 }

#[derive(Debug, Serialize)]
struct ProductDetail {
    id: i64,
    name: String,
    price_cents: i64,
    stock: i64,
    details: String,
    storage: String,
    ingredients: String,
}

#[get("/api/products")]
async fn products(data: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> Result<impl Responder, ApiError> {
    let maybe = query.get("name").cloned();
    let rows = if let Some(name) = maybe {
        sqlx::query("SELECT id, name, price_cents FROM products WHERE name LIKE ? ORDER BY name")
            .bind(format!("%{}%", name))
            .fetch_all(&data.pool)
            .await
            .map_err(|_| ApiError::Server)?
    } else {
        sqlx::query("SELECT id, name, price_cents FROM products ORDER BY name")
            .fetch_all(&data.pool)
            .await
            .map_err(|_| ApiError::Server)?
    };
    let list: Vec<ProductListItem> = rows
        .into_iter()
        .map(|r| ProductListItem {
            id: r.get("id"),
            name: r.get("name"),
            price_cents: r.get("price_cents"),
        })
        .collect();
    Ok(web::Json(list))
}

#[get("/api/products/{id}")]
async fn product_detail(data: web::Data<AppState>, path: web::Path<i64>) -> Result<impl Responder, ApiError> {
    let id = path.into_inner();
    let row = sqlx::query("SELECT id, name, price_cents, stock, details, storage, ingredients FROM products WHERE id = ?")
        .bind(id)
        .fetch_optional(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?
        .ok_or(ApiError::NotFound)?;
    let detail = ProductDetail {
        id: row.get("id"),
        name: row.get("name"),
        price_cents: row.get("price_cents"),
        stock: row.get("stock"),
        details: row.get("details"),
        storage: row.get("storage"),
        ingredients: row.get("ingredients"),
    };
    Ok(web::Json(detail))
}

#[derive(Debug, Deserialize)]
struct OrderItemInput { product_id: i64, quantity: i64 }

#[derive(Debug, Deserialize)]
struct CreateOrderRequest {
    first_name: String,
    last_name: String,
    city: String,
    postal_code: String,
    address: String, // "ulica i numer domu/mieszkania"
    promo_code: Option<String>,
    items: Vec<OrderItemInput>,
}

#[derive(Debug, Serialize)]
struct CreateOrderResponse {
    id: i64,
    status: String,
    created_at: String,
    total_cents: i64,
    total_items: i64,
    items: Vec<OrderItemOutput>,
    first_name: String,
    last_name: String,
    city: String,
    postal_code: String,
    address: String,
    promo_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct OrderItemOutput { product_id: i64, name: String, quantity: i64, price_cents: i64 }

#[post("/api/orders")]
async fn create_order(data: web::Data<AppState>, user: AuthUser, body: web::Json<CreateOrderRequest>) -> Result<impl Responder, ApiError> {
    let mut tx = data.pool.begin().await.map_err(|_| ApiError::Server)?;
    let req = body.into_inner();
    if req.items.is_empty() { return Err(ApiError::BadRequest("Lista produktów nie może być pusta".into())); }

    // sprawdz promo code
    let mut discount_pct: i64 = 0;
    if let Some(code) = &req.promo_code {
        if let Some((pct, active)) = get_discount(&data.pool, code).await? {
            if active { discount_pct = pct; } else { return Err(ApiError::BadRequest("Nieaktywny kod zniżkowy".into())); }
        } else {
            return Err(ApiError::BadRequest("Nieprawidłowy kod zniżkowy".into()));
        }
    }

    // sprawdz stany i policz ceny
    let mut total_cents: i64 = 0;
    let mut total_items: i64 = 0;
    let mut resolved_items: Vec<(OrderItemInput, String, i64)> = Vec::new();
    for it in &req.items {
        let row = sqlx::query("SELECT name, price_cents, stock FROM products WHERE id = ?")
            .bind(it.product_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::Server)?
            .ok_or_else(|| ApiError::BadRequest(format!("Produkt o id {} nie istnieje", it.product_id)))?;
        let name: String = row.get("name");
        let price_cents: i64 = row.get("price_cents");
        let stock: i64 = row.get("stock");
        if it.quantity <= 0 { return Err(ApiError::BadRequest("Ilość musi być > 0".into())); }
        if stock < it.quantity { return Err(ApiError::BadRequest(format!("Brak na stanie produktu {}", name))); }
        total_cents += price_cents * it.quantity;
        total_items += it.quantity;
        resolved_items.push((OrderItemInput{ product_id: it.product_id, quantity: it.quantity }, name, price_cents));
    }

    // apply discount
    if discount_pct > 0 { total_cents = total_cents - (total_cents * discount_pct / 100); }

    // utworz zamowienie
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query("INSERT INTO orders(user_id, status, created_at, total_cents, total_items, first_name, last_name, city, postal_code, address, promo_code) VALUES(?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(user.0)
        .bind(&now)
        .bind(total_cents)
        .bind(total_items)
        .bind(&req.first_name)
        .bind(&req.last_name)
        .bind(&req.city)
        .bind(&req.postal_code)
        .bind(&req.address)
        .bind(&req.promo_code)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Server)?;
    let order_id = res.last_insert_id() as i64;

    // wstaw pozycje i zdejmij stany
    let mut outputs: Vec<OrderItemOutput> = Vec::new();
    for (it, name, price_cents) in resolved_items.into_iter() {
        sqlx::query("INSERT INTO order_items(order_id, product_id, quantity, price_cents) VALUES(?, ?, ?, ?)")
            .bind(order_id)
            .bind(it.product_id)
            .bind(it.quantity)
            .bind(price_cents)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Server)?;
        sqlx::query("UPDATE products SET stock = stock - ? WHERE id = ?")
            .bind(it.quantity)
            .bind(it.product_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Server)?;
        outputs.push(OrderItemOutput{ product_id: it.product_id, name, quantity: it.quantity, price_cents });
    }

    tx.commit().await.map_err(|_| ApiError::Server)?;

    let resp = CreateOrderResponse{
        id: order_id,
        status: "pending".into(),
        created_at: now,
        total_cents,
        total_items,
        items: outputs,
        first_name: req.first_name,
        last_name: req.last_name,
        city: req.city,
        postal_code: req.postal_code,
        address: req.address,
        promo_code: req.promo_code,
    };
    Ok(web::Json(resp))
}

async fn get_discount(pool: &MySqlPool, code: &str) -> Result<Option<(i64, bool)>, ApiError> {
    let row = sqlx::query("SELECT percentage, active FROM discount_codes WHERE code = ?")
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(|_| ApiError::Server)?;
    Ok(row.map(|r| (r.get::<i64, _>("percentage"), r.get::<i64, _>("active") != 0)))
}

#[derive(Debug, Serialize)]
struct OrderListItem { id: i64, status: String, created_at: String, total_cents: i64, total_items: i64 }

#[get("/api/orders")]
async fn list_orders(data: web::Data<AppState>, user: AuthUser) -> Result<impl Responder, ApiError> {
    let rows = sqlx::query("SELECT id, status, created_at, total_cents, total_items FROM orders WHERE user_id = ? ORDER BY id DESC")
        .bind(user.0)
        .fetch_all(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?;
    let list: Vec<OrderListItem> = rows.into_iter().map(|r| OrderListItem{
        id: r.get("id"),
        status: r.get("status"),
        created_at: r.get("created_at"),
        total_cents: r.get("total_cents"),
        total_items: r.get("total_items"),
    }).collect();
    Ok(web::Json(list))
}

#[get("/api/orders/{id}")]
async fn get_order(data: web::Data<AppState>, user: AuthUser, path: web::Path<i64>) -> Result<impl Responder, ApiError> {
    let id = path.into_inner();
    let row = sqlx::query("SELECT id, status, created_at, total_cents, total_items, first_name, last_name, city, postal_code, address, promo_code FROM orders WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user.0)
        .fetch_optional(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?
        .ok_or(ApiError::NotFound)?;
    let items_rows = sqlx::query("SELECT oi.product_id, p.name, oi.quantity, oi.price_cents FROM order_items oi JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?")
        .bind(id)
        .fetch_all(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?;
    let items: Vec<OrderItemOutput> = items_rows.into_iter().map(|r| OrderItemOutput{
        product_id: r.get("product_id"),
        name: r.get("name"),
        quantity: r.get("quantity"),
        price_cents: r.get("price_cents"),
    }).collect();
    let resp = CreateOrderResponse{
        id: row.get("id"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        total_cents: row.get("total_cents"),
        total_items: row.get("total_items"),
        items,
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        city: row.get("city"),
        postal_code: row.get("postal_code"),
        address: row.get("address"),
        promo_code: row.get::<Option<String>, _>("promo_code"),
    };
    Ok(web::Json(resp))
}

#[derive(Debug, Deserialize)]
struct DiscountCheck { code: String }

#[post("/api/discounts/check")]
async fn discount_check(data: web::Data<AppState>, body: web::Json<DiscountCheck>) -> Result<impl Responder, ApiError> {
    let row = sqlx::query("SELECT percentage, active FROM discount_codes WHERE code = ?")
        .bind(&body.code)
        .fetch_optional(&data.pool)
        .await
        .map_err(|_| ApiError::Server)?;
    if let Some(r) = row { 
        let pct: i64 = r.get("percentage");
        let active: i64 = r.get("active");
        Ok(web::Json(serde_json::json!({"valid": active != 0, "percentage": pct})))
    } else {
        Ok(web::Json(serde_json::json!({"valid": false})))
    }
}

#[post("/api/orders/{id}/cancel")]
async fn cancel_order(data: web::Data<AppState>, user: AuthUser, path: web::Path<i64>) -> Result<impl Responder, ApiError> {
    let id = path.into_inner();
    let mut tx = data.pool.begin().await.map_err(|_| ApiError::Server)?;
    // sprawdz status
    let row = sqlx::query("SELECT status FROM orders WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Server)?
        .ok_or(ApiError::NotFound)?;
    let status: String = row.get("status");
    if status != "pending" { return Err(ApiError::BadRequest("Nie można anulować tego zamówienia".into())); }

    // zwróć stany
    let items = sqlx::query("SELECT product_id, quantity FROM order_items WHERE order_id = ?")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::Server)?;
    for r in items.iter() {
        let pid: i64 = r.get("product_id");
        let qty: i64 = r.get("quantity");
        sqlx::query("UPDATE products SET stock = stock + ? WHERE id = ?")
            .bind(qty)
            .bind(pid)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::Server)?;
    }
    // ustaw status canceled
    sqlx::query("UPDATE orders SET status = 'canceled' WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Server)?;
    tx.commit().await.map_err(|_| ApiError::Server)?;
    Ok(web::Json(serde_json::json!({"status":"canceled"})))
}

async fn init_db(pool: &MySqlPool) -> Result<(), sqlx::Error> {
    let script = fs::read_to_string("/home/patryk/rust-api/sql/init.sql").map_err(sqlx::Error::Io)?;
    for stmt in script.split(';') {
        let s = stmt.trim();
        if s.is_empty() || s.starts_with("--") { continue; }
        sqlx::query(s).execute(pool).await?;
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    let db_url = std::env::var("MYSQL_URL").or_else(|_| std::env::var("DATABASE_URL")).unwrap_or_else(|_| "mysql://angflow_admin:TwojeHaslo123!@127.0.0.1:3306/angflow".to_string());
    ensure_mysql_database(&db_url).await;
    println!("Używam bazy danych: {}", db_url);

    let pool = wait_for_mysql_and_connect(&db_url).await;

    init_db(&pool).await.expect("Inicjalizacja bazy nie powiodła się");

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        let rand = Uuid::new_v4().to_string();
        eprintln!("[UWAGA] Brak JWT_SECRET, używam losowego na starcie (tokeny przestaną działać po restarcie): {}", rand);
        rand
    });

    let state = web::Data::new(AppState{
        pool,
        jwt_encoding: EncodingKey::from_secret(jwt_secret.as_bytes()),
        jwt_decoding: DecodingKey::from_secret(jwt_secret.as_bytes()),
    });

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);

    println!("Serwer startuje na porcie {} (HTTP/HTTPS zależnie od konfiguracji)", port);

    let server_factory = move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .app_data(state.clone())
            .service(register)
            .service(login)
            .service(logout)
            .service(products)
            .service(product_detail)
            .service(create_order)
            .service(list_orders)
            .service(get_order)
            .service(discount_check)
            .service(cancel_order)
    };

    let mut server = HttpServer::new(server_factory);
    match load_rustls_config() {
        Ok(tls_config) => {
            println!("HTTPS włączony. Nasłuch na https://{}:{}", host, port);
            server = server.bind_rustls_0_22((host.as_str(), port), tls_config)?;
        }
        Err(e) => {
            eprintln!("[WARN] TLS wyłączony ({}). Nasłuch na http://{}:{}", e, host, port);
            server = server.bind((host.as_str(), port))?;
        }
    }
    server.run().await
}

async fn ensure_mysql_database(url: &str) {
    if let Some(idx) = url.rfind('/') {
        let after = &url[idx+1..];
        let db_name = after.split('?').next().unwrap_or("");
        if !db_name.is_empty() {
            let base = &url[..idx];
            let admin_url = format!("{}/mysql", base);
            match MySqlPoolOptions::new().max_connections(1).connect(&admin_url).await {
                Ok(admin_pool) => {
                    let stmt = format!("CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", db_name);
                    if let Err(e) = sqlx::query(&stmt).execute(&admin_pool).await {
                        eprintln!("[WARN] Nie udało się utworzyć bazy '{}': {}", db_name, e);
                    }
                }
                Err(e) => eprintln!("[WARN] Nie udało się połączyć do serwera MySQL pod {} aby utworzyć bazę {}: {}", admin_url, db_name, e),
            }
        }
    }
}

async fn wait_for_mysql_and_connect(url: &str) -> MySqlPool {
    // Nieskończone próby z narastającym backoffem (1s..10s)
    let mut attempt: u32 = 0;
    let mut backoff = Duration::from_secs(1);
    loop {
        attempt += 1;
        // Spróbuj utworzyć bazę (idempotentnie); jeśli serwer nie wstał, to się nie uda i spróbujemy ponownie
        ensure_mysql_database(url).await;
        match MySqlPoolOptions::new().max_connections(30).connect(url).await {
            Ok(pool) => {
                if attempt > 1 {
                    println!("Połączono z MySQL po {} próbach.", attempt);
                }
                return pool;
            }
            Err(e) => {
                eprintln!(
                    "[INFO] Baza niegotowa lub niedostępna (próba {}): {}. Ponawiam za {}s...",
                    attempt,
                    e,
                    backoff.as_secs()
                );
                sleep(backoff).await;
                if backoff < Duration::from_secs(10) {
                    backoff += Duration::from_secs(1);
                }
            }
        }
    }
}

fn load_rustls_config() -> io::Result<ServerConfig> {
    // Allow overriding paths via env; default to Let's Encrypt paths provided by the user
    let cert_path = env::var("TLS_CERT_PATH")
        .unwrap_or_else(|_| "/etc/letsencrypt/live/securebox.hopto.org/fullchain.pem".to_string());
    let key_path = env::var("TLS_KEY_PATH")
        .unwrap_or_else(|_| "/etc/letsencrypt/live/securebox.hopto.org/privkey.pem".to_string());

    // Read certificate chain
    let mut cert_reader = BufReader::new(File::open(&cert_path)?);
    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nieprawidłowy plik certyfikatu (PEM)"))?;
    if cert_chain.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Plik certyfikatu nie zawiera żadnych certyfikatów"));
    }

    // Read private key (try PKCS#8 first, then RSA PKCS#1)
    let mut key_reader = BufReader::new(File::open(&key_path)?);
    let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_private_keys(&mut key_reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nieprawidłowy klucz prywatny (PKCS#8)"))?;
    if keys.is_empty() {
        // Re-open and try RSA keys
        let mut key_reader = BufReader::new(File::open(&key_path)?);
        keys = rsa_private_keys(&mut key_reader)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nieprawidłowy klucz prywatny (RSA)"))?;
    }
    if keys.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Nie znaleziono klucza prywatnego w pliku"));
    }
    let key = keys.remove(0);

    // Build rustls server config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Błąd konfiguracji TLS: {}", e)))?;
    Ok(config)
}

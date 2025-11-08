-- Schema for MySQL

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  login VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS products (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  price_cents BIGINT NOT NULL,
  price_before_cents BIGINT DEFAULT NULL,
  images JSON DEFAULT NULL,
  stock BIGINT NOT NULL DEFAULT 0,
  details TEXT NOT NULL,
  storage TEXT NOT NULL,
  ingredients TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS discount_codes (
  code VARCHAR(64) PRIMARY KEY,
  percentage INT NOT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orders (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  status VARCHAR(32) NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  total_cents BIGINT NOT NULL,
  total_items BIGINT NOT NULL,
  first_name VARCHAR(255) NOT NULL,
  last_name VARCHAR(255) NOT NULL,
  city VARCHAR(255) NOT NULL,
  postal_code VARCHAR(32) NOT NULL,
  address VARCHAR(255) NOT NULL,
  promo_code VARCHAR(64),
  INDEX idx_orders_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS order_items (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  order_id BIGINT NOT NULL,
  product_id BIGINT NOT NULL,
  quantity BIGINT NOT NULL,
  price_cents BIGINT NOT NULL,
  INDEX idx_items_order_id (order_id),
  INDEX idx_items_product_id (product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS revoked_tokens (
  token VARCHAR(512) PRIMARY KEY,
  exp BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed data
INSERT IGNORE INTO products(name, price_cents, stock, details, storage, ingredients) VALUES
  ('Chleb pszenny', 599, 50, 'Świeże pieczywo.', 'Przechowywać w suchym miejscu.', 'mąka, drożdże, sól'),
  ('Masło ekstra', 1299, 30, 'Masło 82%.', 'Przechowywać w lodówce.', 'śmietanka, kultury bakterii'),
  ('Ser żółty', 1899, 20, 'Ser dojrzewający.', 'Przechowywać w lodówce.', 'mleko, sól, podpuszczka');

-- If you prefer to seed with price_before_cents and images, uncomment and use the following inserts instead:
/*
INSERT IGNORE INTO products(name, price_cents, price_before_cents, images, stock, details, storage, ingredients) VALUES
  ('Chleb pszenny', 599, 699, JSON_ARRAY('orange.png','orange.png'), 50, 'Świeże pieczywo.', 'Przechowywać w suchym miejscu.', 'mąka, drożdże, sól'),
  ('Masło ekstra', 1299, 1499, JSON_ARRAY('orange.png'), 30, 'Masło 82%.', 'Przechowywać w lodówce.', 'śmietanka, kultury bakterii'),
  ('Ser żółty', 1899, 2099, JSON_ARRAY('orange.png','orange.png','orange.png'), 20, 'Ser dojrzewający.', 'Przechowywać w lodówce.', 'mleko, sól, podpuszczka');
*/

INSERT IGNORE INTO discount_codes(code, percentage, active) VALUES('PROMO10', 10, 1);

-- Categories and many-to-many relation
CREATE TABLE IF NOT EXISTS categories (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_categories (
  product_id BIGINT NOT NULL,
  category_id BIGINT NOT NULL,
  PRIMARY KEY (product_id, category_id),
  INDEX idx_pc_product (product_id),
  INDEX idx_pc_category (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Example categories
INSERT IGNORE INTO categories(name) VALUES('Piekarnia'), ('Mleczarnia'), ('Sery');

-- Example mapping (if products seeded with new ids)
/*
INSERT IGNORE INTO product_categories(product_id, category_id) VALUES
  (1, 1),
  (2, 2),
  (3, 3);
*/

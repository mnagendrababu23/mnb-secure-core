-- Optional MySQL tables for mnb-secure-core database-backed cache, rate limiter, and token store.
-- These tables are also auto-created by the Database* classes when first used.

CREATE TABLE IF NOT EXISTS `mnb_cache` (
  `cache_key` VARCHAR(191) NOT NULL,
  `cache_value` MEDIUMTEXT NOT NULL,
  `expires_at` INT NOT NULL,
  `updated_at` INT NOT NULL,
  PRIMARY KEY (`cache_key`),
  KEY `mnb_cache_expires_at_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mnb_rate_limits` (
  `rate_key` VARCHAR(191) NOT NULL,
  `attempts` INT NOT NULL,
  `reset_at` INT NOT NULL,
  `updated_at` INT NOT NULL,
  PRIMARY KEY (`rate_key`),
  KEY `mnb_rate_limits_reset_at_idx` (`reset_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `mnb_api_tokens` (
  `token_hash` CHAR(64) NOT NULL,
  `user_id` VARCHAR(191) NOT NULL,
  `scopes` TEXT NULL,
  `device_id` VARCHAR(191) NULL,
  `device_name` VARCHAR(191) NULL,
  `expires_at` INT NOT NULL,
  `created_at` INT NOT NULL,
  `revoked_at` INT NULL,
  `last_used_at` INT NULL,
  `last_ip` VARCHAR(64) NULL,
  `last_user_agent` VARCHAR(255) NULL,
  PRIMARY KEY (`token_hash`),
  KEY `mnb_api_tokens_user_id_idx` (`user_id`),
  KEY `mnb_api_tokens_expires_at_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

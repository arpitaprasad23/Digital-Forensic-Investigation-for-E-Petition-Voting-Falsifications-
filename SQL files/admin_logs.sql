USE test_db;
CREATE TABLE IF NOT EXISTS admin_logs (
    log_id     INT AUTO_INCREMENT PRIMARY KEY,
    voter_id   INT,
    voter_name VARCHAR(100),
    action     VARCHAR(50),
    detail     VARCHAR(255),
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
);

USE test_db;
CREATE TABLE IF NOT EXISTS admin_snapshots (
    snapshot_id   INT AUTO_INCREMENT PRIMARY KEY,
    snapshot_time DATETIME,
    total_users   INT DEFAULT 0,
    total_votes   INT DEFAULT 0,
    turnout_pct   DECIMAL(5,2) DEFAULT 0.00,
    leading_party VARCHAR(50),
    leading_votes INT DEFAULT 0,
    login_success INT DEFAULT 0,
    login_failed  INT DEFAULT 0,
    not_voted     INT DEFAULT 0
);

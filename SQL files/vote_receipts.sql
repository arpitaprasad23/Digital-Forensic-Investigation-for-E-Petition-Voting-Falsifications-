USE test_db;
CREATE TABLE vote_receipts(
receipt_id     INT AUTO_INCREMENT PRIMARY KEY,
vote_id        INT NOT NULL UNIQUE,
voter_id       INT NOT NULL,
receipt_number VARCHAR(20) NOT NULL UNIQUE,
issued_at      DATETIME NOT NULL,
expires_at     DATETIME NOT NULL,
FOREIGN KEY (vote_id)  REFERENCES ballot_records(vote_id),
  FOREIGN KEY (voter_id) REFERENCES voter_accounts(voter_id)
  );
-- USE test_db;
-- ALTER TABLE vote_receipts ADD COLUMN voter_ip VARCHAR(45) DEFAULT '';
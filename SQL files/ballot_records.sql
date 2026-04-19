USE test_db;
-- CREATE TABLE ballot_records (
--     vote_id INT AUTO_INCREMENT PRIMARY KEY,
--     voter_id INT UNIQUE,
--     party VARCHAR(50),
--     party_full VARCHAR(100),
--     voted_at DATETIME,
--     FOREIGN KEY (voter_id) REFERENCES voter_accounts(voter_id)
-- );
-- -- USE test_db;
-- USE test_db;
ALTER TABLE ballot_records DROP COLUMN country;
ALTER TABLE ballot_records ADD COLUMN city VARCHAR(100) DEFAULT ''; 
ALTER TABLE ballot_records ADD COLUMN state VARCHAR(100) DEFAULT '';
ALTER TABLE ballot_records ADD COLUMN district VARCHAR(100) DEFAULT '';
-- ALTER TABLE ballot_records
-- ADD COLUMN city VARCHAR(100) DEFAULT '',
-- ADD COLUMN state VARCHAR(100) DEFAULT '',
-- ADD COLUMN district VARCHAR(100) DEFAULT 'India';

USE test_db;
-- CREATE TABLE voter_accounts (
--     voter_id INT AUTO_INCREMENT PRIMARY KEY,
--     full_name VARCHAR(100),
--     email VARCHAR(100) UNIQUE,
--     phone_number VARCHAR(15),
--     aadhar_number TEXT,
--     password VARCHAR(255),
--     voter_number VARCHAR(20),
--     date_of_birth DATE,
--     role ENUM('user','admin') DEFAULT 'user'
-- );
-- ALTER TABLE voter_accounts DROP COLUMN country;
ALTER TABLE voter_accounts
-- ADD COLUMN city VARCHAR(100) DEFAULT '',
-- ADD COLUMN state VARCHAR(100) DEFAULT '',
ADD COLUMN district VARCHAR(100) DEFAULT '';


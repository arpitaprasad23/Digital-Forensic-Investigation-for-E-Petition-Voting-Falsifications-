USE test_db;
CREATE TABLE admin_approvals (
    approval_id INT AUTO_INCREMENT PRIMARY KEY,
    proposal_id INT,
    admin_name VARCHAR(100),
    approved BOOLEAN,
    voted_at DATETIME,
    FOREIGN KEY (proposal_id) REFERENCES admin_proposals(proposal_id)
);
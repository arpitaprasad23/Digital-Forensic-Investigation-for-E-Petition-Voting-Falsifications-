USE test_db;
CREATE TABLE admin_proposals (
    proposal_id INT AUTO_INCREMENT PRIMARY KEY,
    proposed_by VARCHAR(100),
    action_type VARCHAR(100),
    action_detail TEXT,
    proposed_at DATETIME,
    status VARCHAR(20)
);
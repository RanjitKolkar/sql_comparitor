-- Tampered SQL Dump
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    password VARCHAR(100)
);

INSERT INTO users (id, username, email, password) VALUES
(1, 'alice', 'alice@example.com', '5f4dcc3b5aa765d61d8327deb882cf99'),
(2, 'bob', 'bob@evilmail.com', '098f6bcd4621d373cade4e832627b4f6');

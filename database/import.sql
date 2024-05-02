CREATE TABLE users (
    id int(11) AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at DATE NOT NULL,
    updated_at DATE NOT NULL,
    role_id int(11)
); 

CREATE TABLE roles (
    id int(11) AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL
);

INSERT INTO roles (type) VALUES ('admin');
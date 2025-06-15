CREATE TABLE nt_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) DEFAULT NULL UNIQUE
);

CREATE TABLE nt_devices_meta (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    netmask VARCHAR(45) NOT NULL,
    gateway VARCHAR(45) NOT NULL,
    description LONGTEXT DEFAULT NULL,
    status VARCHAR(10) DEFAULT "new",
    lastseen DATETIME DEFAULT NULL,
    extra LONGTEXT DEFAULT NULL,
    mac_address varchar(45) NOT NULL,
    type varchar(45) DEFAULT NULL

    INDEX idx_device (device_id),
    INDEX idx_device_ip_address (ip_address),

    FOREIGN KEY (device_id) REFERENCES nt_devices(id)
);

CREATE TABLE nt_users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    firstname VARCHAR(50) NOT NULL,
    lastname VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    last_token VARCHAR(512) DEFAULT NULL;
);

CREATE TABLE nt_users_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reading BOOLEAN DEFAULT FALSE,
    admin_users BOOLEAN DEFAULT FALSE,
    modifying BOOLEAN DEFAULT FALSE;

    INDEX idx_permissions_user_id (user_id),

    FOREIGN KEY (user_id) REFERENCES nt_users(user_id)
);

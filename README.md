# Golden Chess Academy Portal

[![PHP](https://img.shields.io/badge/PHP-7.4%20%7C%208.x-777BB4.svg?logo=php&logoColor=white)](https://www.php.net/)
[![MySQL](https://img.shields.io/badge/MySQL-5.7%20%7C%208.0-4479A1.svg?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5-7952B3.svg?logo=bootstrap&logoColor=white)](https://getbootstrap.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Full-fledged web application specifically designed for chess academies, students, and coaches. Featuring tactical puzzles with scoring, certificate viewer for students, inbox messaging system, forum section with reactions, and user roles.

---

## Table of Contents

- [Features](#-features)
- [Database Schema](#-database-schema)
- [Screenshots & UI Features](#-screenshots--ui-features)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Database Setup](#database-setup)
  - [Running the Project](#running-the-project)
- [Future Improvements](#-future-improvements)
- [Contributing](#-contributing)
- [License](#-license)

---

## Key Features

- **Role-based Authentication:** Interface for Academy Students and Masters/Admins with secure sessions.
- **Chess Strategy Puzzles:** Interactive chess puzzle-solving with instant feedback and scoring system.
- **Certificate Generation:** Creation, viewing, and validation of completion/certificate of attendance to tournaments with automatic audit trail of access.
- **Messaging Service & Inbox:** In-application messaging from students to grand masters/trainer.
- **Discussion & Reactions:** Forums where students discuss and react to the chess strategies posted.
- **Notiflix Alert System:** Modern animations for notifications & loading.

---

## Database Structure

The database, named (`30mm`), uses the following encoding (`utf8mb4_general_ci`) and includes:

```mermaid
erDiagram
    REGISTER {
        int ID PK
        string Username
        string Password
        string Name
        string Email
        string Role
    }

    PUZZLES {
        int ID PK
        string Title
        string FEN
        string Solution
        int Points
    }

    PUZZLE_POINT_AWARDS {
        int ID PK
        int User_ID FK
        int Puzzle_ID FK
        int Points_Awarded
        datetime Timestamp
    }

    MESSAGES {
        int ID PK
        int Sender_ID FK
        int Receiver_ID FK
        string Subject
        text Body
        datetime Sent_At
    }

   CERTIFICATE_VIEW_LOGS {
        int ID PK
        int User_ID FK
        datetime Viewed_At
    }

    COMMENTS o--||{ COMMENT_REACTIONS : has
    REGISTER o--||{ PUZZLE_POINT_AWARDS : earns
    PUZZLES o--||{ PUZZLE_POINT_AWARDS : tracks
    REGISTER o--||{ MESSAGES : sends_and_receives
```

---

## Structure of the Project

```text
Website-for-Chess-Academy/
├── Golden Chess.txt       # Complete SQL database structure with sample data
├── home.php               # Website of the academy for landing portal
├── login.php              # User login page
├── register.php           # Registration for students
├── forgot_password.php    # Forgot password flow
├── student.php            # Dashboard for student
├── studentProfile.php     # Student profile management and statistics
├── master.php             # Dashboard for coaches and masters
├── puzzle.php             # Solver of tactical chess puzzles
├── certificate.php        # Generator and viewer of certificates
├── inbox.php              # Messaging system
├── Rutu1.css, Rutu2.css   # Custom CSS files
├── bootstrap/             # Bootstrap CSS and JS files
├── notiflix/              # Notiflix notification library
├── images/                # Assets including logos
├── LICENSE                # MIT license file
└── README.md              # Documentation of the project
```

---

## Getting Started

### Prerequisites

- **XAMPP/WAMP/LAMP** framework (PHP 7.4+ or 8.x and MySQL/MariaDB).
- Any web browser.

### Database Configuration

1. Log in to **phpMyAdmin** at `http://localhost/phpmyadmin`.
2. Create a database called `30mm` (or simply import it).
3. Import the SQL statements available in the file **[`Golden Chess.txt`](Golden%20Chess.txt)**.

### Executing the Project

1. Copy or move the project directory to the web server’s root folder:
   - For XAMPP: `C:/xampp/htdocs/Website-for-Chess-Academy/`
2. Run **Apache and MySQL** servers in the XAMPP Control Panel.
3. Enter your browser at:
   ```text
   http://localhost/Website-for-Chess-Academy/home.php
   ```

---

## Improvements in the Future

- [ ] Implementation of **Chessboard.js** and **Stockfish.js** engine for playing against the AI.
- [ ] Real-time multiplayer matching using **WebSockets**.
- [ ] Integration of payment gateway for tournament entry fee.
- [ ] Automatic calculation of FIDE performance rating.

---

## License

This project is **MIT Licensed**. See the [LICENSE](LICENSE) for more information.

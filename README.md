# Secure API

A secure API for authentication of users in a SQL database.

## Setup

Clone the repository
```
git clone https://github.com/adamnmartinez/SecureAPI.git
```

Go to new directory
```
cd SecureAPI
```

Install packages
```
npm install
```

### SQL Database
Use the SQL command line tool or a tool like MySQL Workbench to create the following table:
```
CREATE TABLE users (
    id VARCHAR(50) NOT NULL UNIQUE PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    hash VARCHAR(60) NOT NULL
);
```

### Environment Variables
Create a file named `.env` in the root directory of the project with the following structure:
```
# Database Information
DB_USER=<your SQL username>
DB_PASS=<your SQL password>
DB_HOST=<SQL DB host>
DB_PORT=<your SQL port>
DB_CONNECTION_LIMIT=<maximum number of database connections> # default 10
DATABASE=<database name>

# Host Information
API_PORT=<API port> # default 3000
ALLOWED_METHODS=<allowed HTTP methods> # default GET,POST
AUTH_EXPIRE=<JSON Web Token expiration time (e.g. 10m, 30m, 1hr, etc.)> # default 1hr
SECRET_KEY=<JSON Web Token private key>

# Origin
ORIGIN=<allowed request origin>
```

## API Endpoints
`POST /register`: Registers a new user. Request body must contain a unique `username` (string) and `password` (string) field. 
- Usernames must be alphanumeric and may contain underscores, between 3 and 50 characters
- Passwords must be alphanumeric with at least one uppercase letter, lowercase letter, and special character. Must be between 8 and 50 characters
  
`POST /login`: Authenticates a user and generates a JWT. Request body must contain a `username` field (string) and `password` field (string). 
- Returns a JWT authentication token (string).

`POST /protected`: Requires a valid JWT to access this route. Request body must contain a `token` field (string) with a valid authentication token

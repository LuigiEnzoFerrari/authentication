Auth demo with Go, Postgres, SSH bastion, and Metabase

### What this project is
- **auth**: a Go HTTP service exposing basic auth endpoints (register, login, protected, logout).
- **db**: a Postgres database.
- **bastion**: an SSH server used to create a secure tunnel to the database.
- **metabase**: optional UI to explore/query the database.

The Go service currently uses a simple JWT (HS256) and stores users in Postgres with bcrypt-hashed passwords.


## Prerequisites
- Docker and Docker Compose installed
- OpenSSH client on your machine
- An SSH key pair where the public key is placed at `bastion/id_ecdsa.pub` (already present). Ensure your local private key matches that public key.


## Quick start
1) Create the `.env` file at the project root for the Postgres container and app configuration:

```env
# .env (used by docker-compose for db and app)
POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_DB=mydb
# App configuration
# If omitted, defaults are used (SECRET_KEY defaults to "secret-key")
SECRET_KEY=change-me
# Optional: override app port inside container (default 8080)
# APP_PORT=8080
```

2) Start the infrastructure:

```bash
docker compose up -d --build
```

- App will be available on `http://localhost:8080` (if you run it locally; see notes below)
- Metabase will be available on `http://localhost:3000`
- Bastion SSH will listen on `localhost:2222`

3) Create the database table (run once). You can use any Postgres client (psql, DBeaver, Metabase SQL editor, etc.). The required schema is:

```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    hash_password TEXT NOT NULL
);
```

4) Create an SSH tunnel to reach Postgres through the bastion from your local machine:

```bash
ssh -N -f -p 2222 -L 5433:db:5432 luigi@localhost
```

- This forwards your local port `5433` to the containerized Postgres (`db:5432`) via the bastion.
- Make sure your SSH agent has the matching private key for `bastion/id_ecdsa.pub`.

5) Run the Go auth service locally (recommended for now):

The current code uses a connection string pointing to `localhost:5433`. With the tunnel active, simply run:

```bash
cd auth
go run .
```

The service will listen on `http://localhost:8080`.

Note: The app now reads configuration from environment variables. When running in Docker, `docker-compose.yml` supplies:

- `DB_HOST=db`, `DB_PORT=5432`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` (derived from `POSTGRES_*`)
- `APP_PORT=8080`
- `SECRET_KEY` (from `.env`, defaults to `secret-key` if not provided)

When running locally (outside Docker), defaults are used unless you set the following env vars:

```bash
export DB_HOST=localhost
export DB_PORT=5433
export DB_USER=user
export DB_PASSWORD=password
export DB_NAME=mydb
export SECRET_KEY=change-me
export APP_PORT=8080
```


## Services (docker-compose.yml)
- `app`: builds the Go service in `auth/` and exposes `8080:8080`
- `db`: Postgres (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` from `.env`)
- `metabase`: Metabase UI on `3000`
- `bastion`: SSH server on `2222`, user `luigi`, key-only auth


## API reference (current handlers)
Base URL: `http://localhost:8080`

- `GET /` — health/simple hello

- `POST /register`
  - Body (JSON): `{"username":"<string>", "password":"<string>"}`
  - Response: `200 OK` on success

- `POST /login`
  - Body (form-encoded): `username=<string>&password=<string>`
  - Response (JSON): `{"token":"<jwt>"}` on success

- `POST /protected`
  - Headers: `Authorization: Bearer <jwt>`
  - Body (form-encoded): `username=<string>`
  - Response: `200 OK` with a welcome message

- `POST /logout`
  - Headers: `Authorization: Bearer <jwt>`
  - Response: `200 OK` when token is accepted (no server-side invalidation implemented)

### cURL examples
Register:
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}'
```

Login:
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=secret"
```

Protected:
```bash
curl -X POST http://localhost:8080/protected \
  -H "Authorization: Bearer <TOKEN_FROM_LOGIN>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice"
```

Logout:
```bash
curl -X POST http://localhost:8080/logout \
  -H "Authorization: Bearer <TOKEN_FROM_LOGIN>"
```


## Notes and recommendations
- The DB connection string is now configurable via environment variables (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`). Defaults align with the local SSH tunnel flow above.
- For containerized app runtime, the app targets `host=db port=5432` on the Docker network via compose-provided environment.
- Metabase can connect directly to the `db` service on the Docker network and is useful for inspecting tables and running queries.


## Troubleshooting
- Tunnel fails with “Permission denied (publickey)”: ensure your local SSH agent has the private key matching `bastion/id_ecdsa.pub` and that you’re connecting as `luigi` on port `2222`.
- App can’t connect to DB: verify the tunnel is active and listening on `localhost:5433`:
  ```bash
  lsof -i :5433
  ```
  You should see an SSH process bound to 127.0.0.1:5433.
- Metabase not loading: wait a few seconds after `docker compose up -d`; the first start can take longer.


## License
See `LICENSE`.


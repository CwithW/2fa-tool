# 2FA Codes

A small, dependency-free browser tool that generates live TOTP codes from one or more
Base32 secrets or `otpauth://totp` URLs.

Raw secrets must contain at least 16 Base32 characters (`A-Z` and `2-7`). Spaces and hyphens are
ignored, so grouped values such as eight groups of four characters are accepted. Invalid entries
remain visible as error cards with a specific validation message.

## Run locally

```sh
npm start
```

Open `http://localhost:4173`. Run the tests with:

```sh
npm test
```

Use HTTPS when deploying anywhere other than localhost; Web Crypto and clipboard access require a
secure browser context.

## URL behavior

Each non-empty input line is stored in a repeated `token` fragment parameter:

```text
#token=FIRST_SECRET&token=SECOND_SECRET
```

Input updates create browser history entries in short editing bursts. Back and forward navigation
restore the corresponding token list. URL fragments are not included in HTTP requests, so the
secrets are not sent to the static web server.

> [!WARNING]
> This behavior intentionally exposes authenticator secrets to browser history, tab syncing,
> screenshots, browser extensions, and anyone who receives the URL. The app performs no external
> requests.

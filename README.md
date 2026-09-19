# Password Breach Checker

Check if a password has appeared in a known data breach — privately.

- Your password is hashed in your browser (SHA-1).
- Only the **first 5 characters** of the hash are sent to HaveIBeenPwned (k-anonymity).
- The password and full hash **never leave your device**.
- 100% client-side: no server, no accounts, no tracking.

## Run
Open `BreachChecker.html` in any browser, or host this folder on GitHub Pages / Netlify (free).

## Verify
```
node test-breach.cjs
```
13/13 checks pass, including a live HaveIBeenPwned API call and a privacy proof
(only the 5-char hash prefix is ever sent).

## Files
- `BreachChecker.html` — the app
- `breach-checker.cjs` — pure, tested engine
- `test-breach.cjs` — test suite

# TuneBox

A Spotify-style music web app you can install on your phone or PC. Search songs and artists, play 30-second previews, like songs, and build playlists.

**Live demo:** https://mytunebox.vercel.app

## Features

- Search any song or artist, with ready-made mixes and popular artists on the home page
- Music player with play/pause, next/previous, shuffle, repeat, seek bar and volume
- Keyboard shortcuts: `Space` to play/pause, arrow keys for next/previous
- Like songs: guests are saved in the browser, logged-in users are saved to their account
- Create playlists, add and remove songs
- Accounts with username and password, profile photo and display name
- Password recovery code, change password, log out of all devices, delete account
- Installable PWA (Install app / Add to Home Screen) from the menu at the top right
- Works on phone and desktop

## Tech stack

| Part | Technology |
|---|---|
| Frontend | HTML, CSS, vanilla JavaScript (single `index.html`) |
| Backend | Python, FastAPI |
| Database | PostgreSQL (Neon) |
| Auth | bcrypt password hashing, JWT cookie |
| Music data | iTunes Search API (30-second previews) |
| PWA | Web App Manifest and Service Worker |
| Hosting | Vercel |

## Project structure

```
TuneBox/
├── main.py              # FastAPI backend and API routes
├── requirements.txt     # Python dependencies
├── schema.sql           # Database tables
├── static/
│   ├── index.html       # Whole frontend
│   ├── sw.js            # Service worker
│   ├── manifest.webmanifest
│   └── icons/           # PWA icons
└── logo/                # Logo and favicon files
```

## Run locally

1. Clone the repo and open the folder.

   ```
   git clone https://github.com/techno-ankitt/tunebox.git
   cd tunebox
   ```

2. Create a virtual environment and install dependencies.

   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

   On macOS or Linux use `source venv/bin/activate` instead.

3. Create a free PostgreSQL database (for example on [Neon](https://neon.tech)) and run `schema.sql` once in its SQL editor.

4. Set the environment variables.

   | Name | Value |
   |---|---|
   | `DATABASE_URL` | Your PostgreSQL connection string |
   | `JWT_SECRET` | A long random text (16+ characters) |

   You can generate a secret with:

   ```
   python -c "import secrets;print(secrets.token_hex(32))"
   ```

   Windows (Command Prompt):

   ```
   set DATABASE_URL=your_connection_string
   set JWT_SECRET=your_long_random_text
   ```

5. Start the server.

   ```
   uvicorn main:app --reload
   ```

6. Open http://localhost:8000

## Deploy on Vercel

1. Push the project to GitHub.
2. Import the repo in Vercel.
3. Add `DATABASE_URL` and `JWT_SECRET` in **Settings → Environment Variables**.
4. Deploy. Redeploy after changing any variable.

The app must be served over HTTPS for the install option to appear (localhost also works for testing).

## Notes

- Song previews and cover art come from the iTunes Search API. Previews are 30 seconds long.
- Offline, only the app page opens. Songs, search, login, likes and playlists need internet.
- Never commit `.env` files or real secrets to GitHub.

## Author

Made by @techno-ankitt

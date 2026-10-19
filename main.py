"""TuneBox backend: FastAPI + Postgres (login, liked songs, playlists)."""
import base64
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import bcrypt
import jwt
import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, field_validator

BASE = Path(__file__).resolve().parent
COOKIE = "tb_token"
MAX_FAILS, LOCK_MINUTES, TOKEN_DAYS = 5, 15, 30
MAX_PLAYLISTS, MAX_PLAYLIST_SONGS = 30, 500
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())  # keeps login timing similar for unknown users
# Recovery code alphabet: 32 characters, no 0/O/1/I so nobody confuses them when copying by hand
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

app = FastAPI(title="TuneBox")


@app.middleware("http")
async def no_store_for_api(request: Request, call_next):
    """API answers are per-user, so browsers and CDNs must never cache them."""
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------- helpers ----------
def db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise HTTPException(500, "Server is not configured: DATABASE_URL is missing.")
    # autocommit: every single statement is saved at once, no extra COMMIT round trip to Neon.
    # For several statements that must succeed together we use `with con.transaction():` explicitly.
    return psycopg.connect(url, row_factory=dict_row, autocommit=True)


def get_con():
    """ONE database connection per request. FastAPI hands the same connection to current_user()
    and to the handler (a Depends result is cached within a request), then closes it at the end."""
    con = db()
    try:
        yield con
    finally:
        con.close()


def secret() -> str:
    s = os.environ.get("JWT_SECRET", "")
    if len(s) < 16:
        raise HTTPException(500, "Server is not configured: JWT_SECRET is missing or too short.")
    return s


def set_login_cookie(response: Response, user_id: int, token_version: int = 0) -> None:
    """tv = the user's token_version. Bumping it in the DB makes every older cookie invalid."""
    exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_DAYS)
    token = jwt.encode({"sub": str(user_id), "tv": token_version, "exp": exp}, secret(), algorithm="HS256")
    response.set_cookie(
        COOKIE, token, max_age=TOKEN_DAYS * 86400, path="/",
        httponly=True, samesite="lax", secure=bool(os.environ.get("VERCEL")),
    )


def new_recovery_code() -> str:
    """8 random characters shown as XXXX-XXXX. secrets (not random) because it is meant for security."""
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(8))
    return raw[:4] + "-" + raw[4:]


def clean_code(text: str) -> str:
    """Typed codes may have spaces, dashes or small letters. Keep only valid characters, in capitals."""
    return "".join(ch for ch in text.upper() if ch in RECOVERY_ALPHABET)


def hash_code(code: str) -> str:
    """Store only a bcrypt hash of the code, never the code itself. bcrypt is slow on purpose,
    which matters because 8 characters is short: a fast hash (like SHA) could be brute-forced quickly."""
    return bcrypt.hashpw(clean_code(code).encode(), bcrypt.gensalt()).decode()


def current_user(request: Request, con=Depends(get_con)) -> int:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Not logged in.")
    try:
        data = jwt.decode(token, secret(), algorithms=["HS256"])
        uid, tv = int(data["sub"]), int(data.get("tv", 0))  # old cookies have no tv: treated as 0
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Session expired. Please log in again.")
    row = con.execute("SELECT token_version FROM users WHERE id = %s", (uid,)).fetchone()
    if not row or row["token_version"] != tv:  # account deleted, or "log out of all devices" was used
        raise HTTPException(401, "Session expired. Please log in again.")
    return uid


def verify_password(con, uid: int, plain: str) -> None:
    """Check the logged-in user's password, using the same 5-wrong-tries lock as login.
    Returns quietly if correct; raises 401 (wrong) or 429 (locked) otherwise."""
    now = datetime.now(timezone.utc)
    u = con.execute(
        "SELECT password_hash, failed_attempts, locked_until FROM users WHERE id = %s", (uid,)
    ).fetchone()
    if not u:
        raise HTTPException(401, "Account not found.")
    if u["locked_until"] and u["locked_until"] > now:
        mins = max(1, -(-int((u["locked_until"] - now).total_seconds()) // 60))  # round up
        raise HTTPException(429, f"Too many wrong attempts. Try again in {mins} minute{'s' if mins != 1 else ''}.")
    pw = plain.encode()
    if len(pw) <= 72 and bcrypt.checkpw(pw, u["password_hash"].encode()):
        return
    fails = u["failed_attempts"] + 1
    if fails >= MAX_FAILS:
        con.execute("UPDATE users SET failed_attempts = 0, locked_until = %s WHERE id = %s",
                    (now + timedelta(minutes=LOCK_MINUTES), uid))
    else:
        con.execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (fails, uid))
    # autocommit: the counter is already saved, so raising below cannot undo it
    raise HTTPException(401, "Wrong password.")


def owned_playlist(con, pid: int, uid: int) -> dict:
    row = con.execute("SELECT id, name FROM playlists WHERE id = %s AND user_id = %s", (pid, uid)).fetchone()
    if not row:
        raise HTTPException(404, "Playlist not found.")
    return row


# ---------- request models ----------
class Signup(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=100)


class Login(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=100)


class Track(BaseModel):
    trackId: int
    trackName: str = Field(max_length=300)
    artistName: str = Field(max_length=300)
    collectionName: Optional[str] = Field(None, max_length=300)
    artworkUrl100: str = Field(max_length=500)
    previewUrl: str = Field(max_length=500)

    @field_validator("artworkUrl100", "previewUrl")
    @classmethod
    def must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("URL must start with https://")
        return v


class MergeLikes(BaseModel):
    tracks: list[Track] = Field(max_length=500)


class NewPlaylist(BaseModel):
    name: str = Field(min_length=1, max_length=50)


class ProfileIn(BaseModel):
    display_name: str = Field(max_length=40)


class AvatarIn(BaseModel):
    image: str = Field(max_length=200000)


class PasswordIn(BaseModel):
    current: str = Field(max_length=100)
    new_password: str = Field(max_length=100)


class DeleteIn(BaseModel):
    password: str = Field(max_length=100)


class RecoveryIn(BaseModel):
    password: str = Field(max_length=100)


class ResetIn(BaseModel):
    username: str = Field(max_length=40)
    code: str = Field(max_length=100)
    new_password: str = Field(max_length=100)


AVATAR_PREFIX = "data:image/jpeg;base64,"


def valid_avatar(s: str) -> bool:
    """Only small JPEGs produced by the browser's resize step are accepted."""
    if not s.startswith(AVATAR_PREFIX) or len(s) > 150_000:
        return False
    try:
        raw = base64.b64decode(s[len(AVATAR_PREFIX):], validate=True)
    except ValueError:
        return False
    return raw[:3] == b"\xff\xd8\xff"


# ---------- auth ----------
@app.post("/api/signup")
def signup(body: Signup, response: Response, con=Depends(get_con)):
    name = body.username.strip()
    if not USERNAME_RE.match(name):
        raise HTTPException(400, "Username must be 3 to 20 characters: letters, numbers, _ . or -")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")
    pw = body.password.encode()
    if len(pw) > 72:
        raise HTTPException(400, "Password is too long. Use 72 bytes or fewer.")
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
    code = new_recovery_code()  # shown to the user ONCE, only its hash is saved
    try:
        uid = con.execute(
            "INSERT INTO users (username, password_hash, recovery_hash) VALUES (%s, %s, %s) RETURNING id",
            (name, hashed, hash_code(code))
        ).fetchone()["id"]
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "That username is taken. Try another one.")
    set_login_cookie(response, uid, 0)
    return {"username": name, "recovery_code": code}


@app.post("/api/login")
def login(body: Login, response: Response, con=Depends(get_con)):
    name = body.username.strip()
    pw = body.password.encode()
    now = datetime.now(timezone.utc)
    u = con.execute(
        "SELECT id, username, password_hash, failed_attempts, locked_until, token_version "
        "FROM users WHERE lower(username) = lower(%s)", (name,)
    ).fetchone()
    if u and u["locked_until"] and u["locked_until"] > now:
        raise HTTPException(429, f"Too many wrong attempts. Try again in {LOCK_MINUTES} minutes.")
    stored = u["password_hash"].encode() if u else DUMMY_HASH
    ok = len(pw) <= 72 and bcrypt.checkpw(pw, stored) and u is not None
    if not ok:
        if u:
            fails = u["failed_attempts"] + 1
            if fails >= MAX_FAILS:
                con.execute("UPDATE users SET failed_attempts = 0, locked_until = %s WHERE id = %s",
                            (now + timedelta(minutes=LOCK_MINUTES), u["id"]))
            else:
                con.execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (fails, u["id"]))
        # autocommit: the counter is already saved, so raising below cannot undo it
        raise HTTPException(401, "Wrong username or password.")
    con.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s", (u["id"],))
    set_login_cookie(response, u["id"], u["token_version"])
    return {"username": u["username"]}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/logout-all")
def logout_all(response: Response, uid: int = Depends(current_user), con=Depends(get_con)):
    """Log out every device, including this one, then give this device a fresh cookie so it stays logged in."""
    tv = con.execute(
        "UPDATE users SET token_version = token_version + 1 WHERE id = %s RETURNING token_version", (uid,)
    ).fetchone()["token_version"]
    set_login_cookie(response, uid, tv)
    return {"ok": True}


@app.get("/api/me")
def me(uid: int = Depends(current_user), con=Depends(get_con)):
    u = con.execute(
        "SELECT username, display_name, avatar, (recovery_hash IS NOT NULL) AS has_recovery "
        "FROM users WHERE id = %s", (uid,)).fetchone()
    if not u:
        raise HTTPException(401, "Account not found.")
    return u


@app.put("/api/profile")
def update_profile(body: ProfileIn, uid: int = Depends(current_user), con=Depends(get_con)):
    name = body.display_name.strip() or None
    con.execute("UPDATE users SET display_name = %s WHERE id = %s", (name, uid))
    return {"display_name": name}


@app.put("/api/profile/avatar")
def set_avatar(body: AvatarIn, uid: int = Depends(current_user), con=Depends(get_con)):
    if not valid_avatar(body.image):
        raise HTTPException(400, "That photo isn't valid. Please choose a JPG or PNG image.")
    con.execute("UPDATE users SET avatar = %s WHERE id = %s", (body.image, uid))
    return {"ok": True}


@app.delete("/api/profile/avatar")
def remove_avatar(uid: int = Depends(current_user), con=Depends(get_con)):
    con.execute("UPDATE users SET avatar = NULL WHERE id = %s", (uid,))
    return {"ok": True}


@app.post("/api/password")
def change_password(body: PasswordIn, response: Response, uid: int = Depends(current_user), con=Depends(get_con)):
    new = body.new_password.encode()
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters.")
    if len(new) > 72:
        raise HTTPException(400, "New password is too long. Use 72 bytes or fewer.")
    verify_password(con, uid, body.current)
    # token_version + 1 logs out every other device; this device gets a fresh cookie below
    tv = con.execute(
        "UPDATE users SET password_hash = %s, failed_attempts = 0, locked_until = NULL, "
        "token_version = token_version + 1 WHERE id = %s RETURNING token_version",
        (bcrypt.hashpw(new, bcrypt.gensalt()).decode(), uid)).fetchone()["token_version"]
    set_login_cookie(response, uid, tv)
    return {"ok": True}


@app.post("/api/recovery")
def make_recovery_code(body: RecoveryIn, uid: int = Depends(current_user), con=Depends(get_con)):
    """Make a NEW recovery code (needs the password). The old code stops working immediately."""
    code = new_recovery_code()
    verify_password(con, uid, body.password)
    con.execute(
        "UPDATE users SET recovery_hash = %s, recovery_failed = 0, recovery_locked_until = NULL WHERE id = %s",
        (hash_code(code), uid))
    return {"recovery_code": code}


@app.post("/api/recovery/reset")
def reset_password(body: ResetIn, response: Response, con=Depends(get_con)):
    """Forgot password: username + recovery code + new password. Works without being logged in.
    The code is used up only when the reset succeeds, and a NEW code is returned at the end."""
    new = body.new_password.encode()
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters.")
    if len(new) > 72:
        raise HTTPException(400, "New password is too long. Use 72 bytes or fewer.")
    name, code = body.username.strip(), clean_code(body.code)
    now = datetime.now(timezone.utc)
    wrong = False
    # `with con.transaction()` = BEGIN ... COMMIT around this block. FOR UPDATE: if someone sends many
    # guesses at the same moment, they wait in a queue here, so the 5-tries counter cannot be beaten
    # by sending requests in parallel. The lock is held until the block ends.
    with con.transaction():
        u = con.execute(
            "SELECT id, username, recovery_hash, recovery_failed, recovery_locked_until "
            "FROM users WHERE lower(username) = lower(%s) FOR UPDATE", (name,)
        ).fetchone()
        if u and u["recovery_locked_until"] and u["recovery_locked_until"] > now:
            mins = max(1, -(-int((u["recovery_locked_until"] - now).total_seconds()) // 60))
            raise HTTPException(429, f"Too many wrong attempts. Try again in {mins} minute{'s' if mins != 1 else ''}.")
        has_code = bool(u and u["recovery_hash"])
        stored = u["recovery_hash"].encode() if has_code else DUMMY_HASH  # unknown user: same work, same time
        ok = bcrypt.checkpw(code.encode(), stored) and len(code) == 8 and has_code
        if not ok:
            if u:  # its own counter, so a stranger cannot lock the owner out of normal login
                fails = u["recovery_failed"] + 1
                if fails >= MAX_FAILS:
                    con.execute("UPDATE users SET recovery_failed = 0, recovery_locked_until = %s WHERE id = %s",
                                (now + timedelta(minutes=LOCK_MINUTES), u["id"]))
                else:
                    con.execute("UPDATE users SET recovery_failed = %s WHERE id = %s", (fails, u["id"]))
            wrong = True  # do NOT raise inside the block: that would roll back the counter we just saved
        else:
            new_code = new_recovery_code()
            tv = con.execute(
                "UPDATE users SET password_hash = %s, recovery_hash = %s, recovery_failed = 0, "
                "recovery_locked_until = NULL, failed_attempts = 0, locked_until = NULL, "
                "token_version = token_version + 1 WHERE id = %s RETURNING token_version",
                (bcrypt.hashpw(new, bcrypt.gensalt()).decode(), hash_code(new_code), u["id"])
            ).fetchone()["token_version"]
    if wrong:
        raise HTTPException(401, "Username or code is wrong.")  # same message for every kind of failure
    set_login_cookie(response, u["id"], tv)  # all older logins stop working; this device is logged in
    return {"username": u["username"], "recovery_code": new_code}


@app.post("/api/account/delete")
def delete_account(body: DeleteIn, response: Response, uid: int = Depends(current_user), con=Depends(get_con)):
    """Permanently delete the account. Likes, playlists and songs go too (ON DELETE CASCADE)."""
    verify_password(con, uid, body.password)
    con.execute("DELETE FROM users WHERE id = %s", (uid,))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


# ---------- liked songs ----------
@app.get("/api/likes")
def list_likes(uid: int = Depends(current_user), con=Depends(get_con)):
    rows = con.execute(
        "SELECT data FROM liked_songs WHERE user_id = %s ORDER BY created_at DESC LIMIT 1000", (uid,)
    ).fetchall()
    return [r["data"] for r in rows]


@app.put("/api/likes/{track_id}")
def like(track_id: int, track: Track, uid: int = Depends(current_user), con=Depends(get_con)):
    if track.trackId != track_id:
        raise HTTPException(400, "Track id mismatch.")
    con.execute(
        "INSERT INTO liked_songs (user_id, track_id, data) VALUES (%s, %s, %s) "
        "ON CONFLICT (user_id, track_id) DO NOTHING", (uid, track_id, Jsonb(track.model_dump())))
    return {"ok": True}


@app.delete("/api/likes/{track_id}")
def unlike(track_id: int, uid: int = Depends(current_user), con=Depends(get_con)):
    con.execute("DELETE FROM liked_songs WHERE user_id = %s AND track_id = %s", (uid, track_id))
    return {"ok": True}


@app.post("/api/likes/merge")
def merge_likes(body: MergeLikes, uid: int = Depends(current_user), con=Depends(get_con)):
    """Move a guest's locally saved likes into their new account."""
    with con.transaction():  # all songs are saved together or none
        for t in body.tracks:
            con.execute(
                "INSERT INTO liked_songs (user_id, track_id, data) VALUES (%s, %s, %s) "
                "ON CONFLICT (user_id, track_id) DO NOTHING", (uid, t.trackId, Jsonb(t.model_dump())))
    return {"added": len(body.tracks)}


# ---------- playlists ----------
@app.get("/api/playlists")
def list_playlists(uid: int = Depends(current_user), con=Depends(get_con)):
    return con.execute(
        "SELECT p.id, p.name, COUNT(s.track_id)::int AS count FROM playlists p "
        "LEFT JOIN playlist_songs s ON s.playlist_id = p.id "
        "WHERE p.user_id = %s GROUP BY p.id ORDER BY p.created_at", (uid,)
    ).fetchall()


@app.post("/api/playlists")
def create_playlist(body: NewPlaylist, uid: int = Depends(current_user), con=Depends(get_con)):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Playlist name can't be empty.")
    n = con.execute("SELECT COUNT(*) AS n FROM playlists WHERE user_id = %s", (uid,)).fetchone()["n"]
    if n >= MAX_PLAYLISTS:
        raise HTTPException(400, f"You can have up to {MAX_PLAYLISTS} playlists.")
    return con.execute(
        "INSERT INTO playlists (user_id, name) VALUES (%s, %s) RETURNING id, name", (uid, name)
    ).fetchone()


@app.get("/api/playlists/{pid}")
def get_playlist(pid: int, uid: int = Depends(current_user), con=Depends(get_con)):
    p = owned_playlist(con, pid, uid)
    rows = con.execute(
        "SELECT data FROM playlist_songs WHERE playlist_id = %s ORDER BY position", (pid,)).fetchall()
    return {"id": p["id"], "name": p["name"], "tracks": [r["data"] for r in rows]}


@app.delete("/api/playlists/{pid}")
def delete_playlist(pid: int, uid: int = Depends(current_user), con=Depends(get_con)):
    owned_playlist(con, pid, uid)
    con.execute("DELETE FROM playlists WHERE id = %s AND user_id = %s", (pid, uid))
    return {"ok": True}


@app.put("/api/playlists/{pid}/songs/{track_id}")
def add_song(pid: int, track_id: int, track: Track, uid: int = Depends(current_user), con=Depends(get_con)):
    if track.trackId != track_id:
        raise HTTPException(400, "Track id mismatch.")
    owned_playlist(con, pid, uid)
    n = con.execute("SELECT COUNT(*) AS n FROM playlist_songs WHERE playlist_id = %s", (pid,)).fetchone()["n"]
    if n >= MAX_PLAYLIST_SONGS:
        raise HTTPException(400, f"A playlist can hold up to {MAX_PLAYLIST_SONGS} songs.")
    con.execute(
        "INSERT INTO playlist_songs (playlist_id, track_id, data, position) VALUES "
        "(%s, %s, %s, (SELECT COALESCE(MAX(position), 0) + 1 FROM playlist_songs WHERE playlist_id = %s)) "
        "ON CONFLICT (playlist_id, track_id) DO NOTHING", (pid, track_id, Jsonb(track.model_dump()), pid))
    return {"ok": True}


@app.delete("/api/playlists/{pid}/songs/{track_id}")
def remove_song(pid: int, track_id: int, uid: int = Depends(current_user), con=Depends(get_con)):
    owned_playlist(con, pid, uid)
    con.execute("DELETE FROM playlist_songs WHERE playlist_id = %s AND track_id = %s", (pid, track_id))
    return {"ok": True}


# ---------- page ----------
@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


# ---------- PWA files (install support) ----------
ICON_FILES = {"icon-192.png", "icon-512.png", "apple-touch-icon.png"}


@app.get("/sw.js")
def service_worker():
    return FileResponse(BASE / "static" / "sw.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})


@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(BASE / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/icons/{name}")
def icon(name: str):
    if name not in ICON_FILES:
        raise HTTPException(404, "Not found.")
    return FileResponse(BASE / "static" / "icons" / name, media_type="image/png")
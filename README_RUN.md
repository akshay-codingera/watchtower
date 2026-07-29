# Running WATCHTOWER on your laptop (Windows)

## What this actually is
There's no `index.html` to open. WATCHTOWER is a Python program that runs a
small web server on your machine. You start the program, and *then* you open
a browser and point it at that server. The dashboard only exists while
`core.py` is running.

## One-time setup
1. Make sure Python 3.11+ is installed (`python --version` in a terminal).
   If not: https://www.python.org/downloads/ — check "Add python.exe to PATH"
   during install.
2. Put this whole `watchtower` folder at `D:\Projects\watchtower`.

## Every time you want to run it
**Easiest:** double-click `run_watchtower.bat` in the project folder.
It creates a virtual environment, installs dependencies, and starts the
server automatically.

**Manual equivalent**, in a terminal (cmd or PowerShell):
```
cd D:\Projects\watchtower
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python core.py
```

You'll see log lines ending with something like:
```
Dashboard: http://localhost:5000/
```

## Viewing the dashboard
With `core.py` still running in that terminal window, open a browser and go to:
```
http://localhost:5000/
```
It'll redirect you to a login page.

- **Username:** `admin`
- **Password:** `watchtower123`   (this is a placeholder — change it, see below)

Leave the terminal window open — closing it, or pressing CTRL+C in it, stops
the server and the dashboard.

## Changing the admin password
The password isn't stored in plaintext — `config.ini` stores a hash of it.
Generate a new hash and drop it in:

```
python -c "import hashlib; print(hashlib.sha256(b'your_new_password').hexdigest())"
```

Copy the printed hash into `config.ini`:
```ini
[auth]
admin_password_hash = <paste the hash here>
```

Restart `core.py` for it to take effect.

## What's actually working right now
- Log intake: UDP port 5140 and TCP port 5141 are listening and writing
  incoming syslog messages to `logs/syslog.db` (SQLite).
- The dashboard: login, session handling, account lockout after repeated
  failed logins, and the audit trail all work — every page in the nav loads.
- Log format parsing (turning a raw log line into structured fields like
  hostname/severity/app name) is still a placeholder — records are stored,
  but not deeply parsed yet. That's `pipeline/` and is flagged as unfinished
  in `core.py`'s own comments.
- Some JS-driven widgets on individual pages (live streaming feed, device
  registry actions, the control panel) call API endpoints that touch
  `dispatch/` and `beacon/` — those weren't part of this fix pass, so a few
  buttons on those pages may still error out even though the page itself
  loads fine.

## Testing that log intake works
From another terminal, send a test log line:
```
python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'<134>test message from laptop', ('127.0.0.1', 5140))"
```
Then check the dashboard's log feed / chronicle pages, or inspect the DB directly
(unparsed test messages land in `system_logs` by default):
```
python -c "import sqlite3; c=sqlite3.connect('logs/syslog.db'); print(c.execute('SELECT id, received_at, raw_message FROM system_logs ORDER BY id DESC LIMIT 5').fetchall())"
```

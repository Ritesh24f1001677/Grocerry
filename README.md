# Gather — local shared grocery app

Gather runs entirely on your computer with a Node.js backend and a local SQLite database. It has separate email/password accounts, invite-code households, shared grocery items and live updates between signed-in browsers.

## Run it

1. Install Node.js 22.5 or newer.
2. In this folder run `npm start` (or `node server.js`).
3. Open `http://localhost:3000` in a browser and create an account.
4. Create a household; give the invite code to another person. They open the same address, create their own account and join with that code.

The database is created automatically at `data/gather.sqlite` and persists when the server stops. No npm packages or cloud account are needed.

## Use on a local network

The server listens on all network interfaces. Find this computer's local IPv4 address, then other devices on the same trusted Wi-Fi can open `http://<computer-ip>:3000`. The computer must keep the app running; your firewall may ask whether to allow Node.js on your private network.

This local prototype uses HTTP and is intended for a trusted home network. Do not expose port 3000 to the public internet. Passwords are hashed with Node's scrypt, sessions are stored as hashes, and all list access is checked by the backend.

## Data

SQLite file: `data/gather.sqlite`. Back up this file to preserve accounts, lists and items. The old hosted `schema.sql` is no longer needed for this local version.

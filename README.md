# Gather — local and Vercel grocery app

Gather supports a local mode (Node.js + SQLite) and a Vercel deployment (Vercel Functions + Neon Postgres). It has separate accounts, household invite codes, shared lists, and cross-device list refreshes.

## Run locally

1. Install Node.js 22.5 or newer.
2. Run `npm start` in this folder.
3. Open `http://localhost:3000`, create an account and a household, then share the invite code.

The local database is created at `data/gather.sqlite`. It is ignored by Git and persists on this computer.

## Deploy on Vercel

1. Connect a Neon Postgres database to the Vercel project and make sure its connection string is available as `DATABASE_URL` in Production (and Preview if desired). The Vercel API creates its tables on first request.
2. Import the GitHub repository `Ritesh24f1001677/Grocerry` into Vercel, or from this folder run `vercel` to link/create the project, then `vercel --prod`.
3. Open the production URL, create an account, and create a household. Members join using the invite code.

The Vercel version uses Neon for persistent data and polls the API every 2.5 seconds for updates, because Vercel Functions are short-lived and the local SQLite file cannot persist there.

## Network note

The local app can be shared on a trusted home Wi-Fi network while the computer stays running. Do not expose the local HTTP server directly to the public internet.

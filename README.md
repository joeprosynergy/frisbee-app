# EasyGameRoster

Weekly pickup-game signups. People open a link, type their name, and tap "I'm in." Live at [easygameroster.com](https://www.easygameroster.com).

## Tech stack

Listed in the order things flow, from source to user:

1. **GitHub** - where the code lives (everything starts here)
2. **Vercel** - deploys the code from GitHub and serves the site
3. **Supabase** - the backend the app talks to
4. **PostgreSQL** - the database, inside Supabase
5. **Web Push** - notifications out to people's devices

In one line: GitHub -> Vercel -> Supabase (Postgres) -> Web Push.

# Surelin Web

Free-first Surelin web foundation connected to the existing Surelin Supabase project.

### Included
- Username + password accounts; no email field and no Discord integration
- Followers and friend requests
- Profiles and Sura balance display
- Games discovery and Your Games
- Browser 3D editor with cube/sphere/plane/light tools, selection, transform fields, save and publish
- Admin panel with user moderation
- Port 3000
- `.env` prefilled with the current Surelin Supabase URL, publishable key, and deployed Edge Function URL

### Run
Requires Node.js 22+.

```bash
cd surelin-web
npm install
npm start
```
Open http://127.0.0.1:3000

The first account created through this site becomes the initial admin. Passwords are hashed inside the Supabase Edge Function; no password is stored in the browser or in plaintext.

Do not add a Supabase secret/service-role key to this project. The browser only gets the publishable key.


### Important
The Surelin API uses its own signed session token, so the Edge Function must have `verify_jwt = false`. The included `supabase/config.toml` keeps that setting for future deployments.

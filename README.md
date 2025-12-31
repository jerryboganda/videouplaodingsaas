# Secure Video Dashboard

A production-ready, single-page video management dashboard with enhanced security features.

## Security Features

### Architecture
- **Admin authentication**: Username/password + email OTP (2FA)
- **Password reset**: Email reset link
- **API proxy**: The browser calls only the local backend (`/api/*`). Provider credentials are stored server-side in the session.

## Features

- **Admin Sign-in**: Username/password + email verification code
- **Session-based library connection**: Enter Library ID and API Key per session
- **Video Gallery**: Grid layout with thumbnails
- **Video Upload**: Multi-file, parallel uploads, per-file progress bars
- **Video Management**: Delete videos with confirmation
- **Video Details / Edit**: Rename videos and move between collections
- **Responsive Design**: Works on desktop and mobile
- **Modern UI**: Clean, professional interface

## Quick Start

### Prerequisites

- Node.js 18+
- An SMTP account (required to send OTP + reset emails)

### Setup

1. Create and configure `.env`
   - Use the included `.env` / `.env.example` as a template
   - Set:
     - `SESSION_SECRET`
     - `ADMIN_USERNAME` / `ADMIN_PASSWORD`
     - `ADMIN_2FA_EMAIL`
     - `SMTP_*` settings

2. Install dependencies
   - `npm install`

3. Start the server
   - `npm start`
   - Or double-click `start-dashboard.bat`

4. Open the app
   - http://localhost:5173

### LAN Access

To access the dashboard from another device on the same network:

- Start the server (it binds to all interfaces by default via `HOST=0.0.0.0`).
- Open:
  - `http://<YOUR-PC-IP>:5173`
- If it does not load, allow **Node.js** through **Windows Firewall** for private networks.

## Security Notes

- Provider API keys are not placed in the static frontend source code.
- Provider API calls are made server-side via `/api/*` routes.
- OTP and password reset require properly configured SMTP.

## Project Files

- `index.html` Frontend
- `server.js` Backend (auth + proxy)
- `.env` Local configuration (not for committing)
- `.env.example` Template

## Browser Compatibility

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

## Production Considerations

For production use, consider:
1. Adding HTTPS
2. Implementing rate limiting
3. Adding file size validation
4. Implementing progress indicators for uploads
5. Adding video preview functionality
6. Implementing bulk operations

## License

MIT License - Feel free to use in commercial projects

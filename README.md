# 📝 Notelify

🌐 Live Demo: [Notelify](https://notelify-6n5e.onrender.com/)

Notelify is a secure, modern **Flask-based note-taking app** with multiple authentication methods, email verification, and JWT-protected sessions. Users can **register, login (via email or Google), verify via OTP, and manage notes** safely with SQLite as the database backend.  

---

## 🚀 Features

- 🔑 **User Authentication**
  - Register with email & password  
  - Secure password hashing with `werkzeug.security`  
  - Email OTP verification (expires in 5 minutes)  
  - Google OAuth login  

- 🔒 **Security**
  - JWT authentication stored in cookies  
  - Environment variables for secrets & credentials  
  - No sensitive data in source code  

- 🗒️ **Note Management**
  - Add, edit, delete notes  
  - Notes linked to individual users  
  - Cascade deletion on user removal  

- 📧 **Email Integration**
  - Send OTP verification emails via **Brevo API** (recommended for production)
  - Optional Gmail SMTP support for development/testing
  - Fully configurable via environment variables
  
- 🌐 **Deployment**
  - Live on [Render](https://notelify-6n5e.onrender.com/)
  - Can be deployed for free using Render etc.

- ⚡ **Tech Stack**
  - Backend: Flask
  - Frontend: HTML, CSS, JS, Tailwind
  - Auth: JWT + Google OAuth  
  - Database: SQLite  
  - Email: Flask-Mail

### ⚙️ Environment Variables
| Variable | Description |
|----------|-------------|
| SECRET_KEY | Flask session secret |
| JWT_SECRET_KEY | Secret for JWT signing |
| MAIL_USERNAME | Email address for SMTP (optional) |
| MAIL_PASSWORD | SMTP password or app password (optional) |
| BREVO_API_KEY | Brevo API key for sending OTP emails |
| GOOGLE_CLIENT_ID | Google OAuth client ID |
| CLIENT_SECRET | Google OAuth client secret |
| OAUTH_REDIRECT_URI | OAuth redirect URI (must match Google console) |





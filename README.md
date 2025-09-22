# 📝 Notelify

🌐 Live Demo: [Notelify](https://notelify-6n5e.onrender.com/)

Notelify is a secure, modern **Flask-based note-taking app** with multiple authentication methods, email verification, and JWT-protected sessions.  
Users can **register, login (via email or Google), verify via OTP, and manage notes** safely with SQLite as the database backend.  

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
  - Gmail SMTP support for sending OTP codes  
  - Configurable with environment variables  

- ⚡ **Tech Stack**
  - Backend: Flask
  - Frontend: HTML, CSS, JS, Tailwind
  - Auth: JWT + Google OAuth  
  - Database: SQLite  
  - Email: Flask-Mail


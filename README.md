# PROJECT(CYBERSECFEILD)

PROJECT(CYBERSECFEILD) is a full-stack cyber defense platform designed to provide advanced website security, real-time threat monitoring, and automated protection tools. It combines a modern Next.js frontend with a powerful Django backend and advanced security scanning tools.

---

## 🔐 Features

### Frontend (Next.js + Tailwind CSS)
- User Authentication (Login / Signup)
- Dashboard with:
  - AI-Powered Threat Analyzer
  - Real-Time Security Monitor
  - Blockchain-Based Security Ledger
  - System Health & Activity Feed
  - Tool-Specific Scanner & Website Analyzer
- Security Tools:
  - WAF Protection
  - SSL Management
  - Bot Management
  - DDoS Protection
  - Deploy Protection
  - Vulnerability Scanner
- Responsive UI with modern design components

### Backend (Django + REST API)
- User Management
- Threat Intelligence System
- Bot Detection & Mitigation
- SSL & Certificate Monitoring
- Middleware for Real-Time Analysis
- Task Scheduler (Celery)
- Centralized Logging (Security & Django logs)

---

## 🛠 Tech Stack

- **Frontend:** Next.js, TypeScript, Tailwind CSS, ShadCN UI
- **Backend:** Django, Django REST Framework
- **Security Tools:** Custom Python Modules
- **Database:** PostgreSQL (or any preferred DB)
- **Task Queue:** Celery + Redis
- **Testing:** Jest, Cypress
- **Version Control:** Git + GitHub

---

## 📂 Project Structure

```

/app                → Frontend pages (Next.js routing)
/components         → Reusable UI components
/hooks              → Custom React hooks
/backend            → Node backend (if used)
/django\_backend     → Django backend with all APIs
/public             → Static files and images
/styles             → Global CSS and Tailwind

````

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/IROMIMPULSE15/FIFTH-M-.git
cd FIFTH-M-
````

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 3. Backend (Django) Setup

```bash
cd django_backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

---

## ✅ Tests

### Frontend Tests

```bash
npm run test
```

### End-to-End Tests (Cypress)

```bash
npx cypress open
```

---

## 📌 Roadmap

* [x] Frontend Dashboard UI
* [x] Threat Monitoring Integration
* [x] Basic WAF and SSL tools
* [ ] Email Alerts on Breach Detection
* [ ] Multi-Tenant Support
* [ ] Real-Time WebSocket Alerts

---

## 🤝 Contributors

* Jagananmol Daneti (Full Stack Developer)
* Bhaskar Sanam (Artificial Intelligence And Machine Learning Enthusiast)
---

## 📃 License

This project is licensed under the MIT License.

```
```

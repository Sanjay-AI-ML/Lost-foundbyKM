# 🧭 Lost & Found Portal

A modern, responsive full-stack Django web application designed to connect people who lost items with those who found them. Features automated notifications, item claim verification workflows, rich image uploads, advanced search, and user profile management.

## CyberAccess integration

The Django server now connects to CyberAccess using one tenant API key in `.env`.
The key stays on the server; no CyberAccess JWT or admin credential is needed.
Copy `.env.example`, set your key and backend URL, then restart Django.
Protected claim reads and item mutations enforce CyberAccess's allow/deny/block decisions.

For the local interactive test, enable `CYBERACCESS_DEMO_ENABLED=true`, run
`python manage.py seed_cyberaccess_demo`, and open `/cyberaccess/demo/`.
The demo is restricted to loopback development access and uses synthetic users and claims.

---

## 🌟 Key Features

- **🔐 User Authentication & Profiles:**
  - Secure registration, login, logout, and password change.
  - User profiles with avatar uploads, phone number, bio, and address.
  - Personal dashboard tracking all posted items and claims.

- **📦 Lost & Found Listings:**
  - Post lost or found items with photos, categories, item status, location, and date.
  - Category filtering, real-time keyword search, and dedicated lost/found feeds.
  - Edit and delete permissions limited to item creators.

- **🤝 Claims & Verification System:**
  - Secure claim request submission with proof descriptions and optional proof photos.
  - Item finders can review claims and approve or reject them with feedback notes.
  - Visual claim statuses: *Pending*, *Approved*, *Rejected*.

- **🔔 In-App & Email Notifications:**
  - Automated alerts when claims are filed, approved, or rejected.
  - Notification center with unread counters and mark-as-read functionality.

- **🎨 Modern UI/UX:**
  - Glassmorphic card design with smooth CSS micro-interactions and transitions.
  - Mobile-responsive navigation and accessible HTML5 semantics.

---

## 📂 Project Structure

```
lost_found_project/
├── manage.py
├── requirements.txt
├── .gitignore
├── README.md
├── lost_found_project/     # Project configuration (settings, urls, wsgi, asgi)
├── accounts/               # User authentication, profiles, views, forms, templates
├── items/                  # Item catalog, lost/found posts, category filters, search
├── claims/                 # Verification and claims processing workflow
├── notifications/          # In-app notifications and email alert templates
├── templates/              # Shared base layouts, navigation, footers, error pages
├── static/                 # Global styles, JavaScript, and branding images
├── media/                  # User uploads (profiles, lost items, found items)
├── docs/                   # Documentation, ER diagrams, and use case diagrams
└── database/               # SQLite database and backup storage
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+
- `pip` package manager

### 2. Installation
Clone the repository and install dependencies:
```bash
python -m pip install -r requirements.txt
```

### 3. Database Setup & Migrations
Run the initial migrations to set up database tables:
```bash
python manage.py makemigrations
python manage.py migrate
```

### 4. Create an Admin User (Optional)
```bash
python manage.py createsuperuser
```

### 5. Start Development Server
```bash
python manage.py runserver
```
Visit `http://127.0.0.1:8000/` in your browser.

---

## 🧪 Running Tests

CyberAccess API-key integration also drives the portal's notification bell, denied-request
warnings, and a server-verified quarantine page with a countdown. Denied and blocked
decisions appear in the Django server log; the API key remains server-only. Configure
notification grouping and optional file logging using `.env.example`.

```bash
python manage.py test
```

---

## 📄 License
This project is open-source under the MIT License.

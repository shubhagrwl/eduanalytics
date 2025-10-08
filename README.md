# EduAnalytics - Educational Reporting Framework

> A comprehensive backend system for tracking, analyzing, and reporting student performance, classroom engagement, and content effectiveness across educational applications.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Reports](#reports)
- [Event Tracking](#event-tracking)
- [Deployment](#deployment)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)

## 🎯 Overview

EduAnalytics is a reporting and analytics backend designed for educational platforms that synchronize Whiteboard (teacher) and Notebook (student) applications. It provides:

- **Real-time quiz synchronization** between teachers and students via WebSocket
- **Comprehensive event tracking** for user interactions across both apps
- **Advanced reporting** on student performance, classroom engagement, and content effectiveness
- **Scalable architecture** designed to handle 1,000 schools with 30 classrooms each and 30 students per classroom (~900,000 students)

### Use Cases

1. **Teachers** can:
   - Create and manage quizzes
   - Conduct real-time quiz sessions with students
   - View classroom engagement metrics
   - Analyze content effectiveness

2. **Students** can:
   - Participate in live quizzes
   - Submit answers via WebSocket or REST API
   - Track their own performance

3. **Admins** can:
   - Generate comprehensive reports across schools
   - Analyze trends and patterns
   - Monitor system usage

## ✨ Features

### Core Features
- ✅ **User Management** - Multi-role authentication (admin, teacher, student)
- ✅ **Quiz System** - Create quizzes and manage quiz sessions
- ✅ **Real-time Sync** - WebSocket-based live quiz sessions
- ✅ **Event Tracking** - Event queue system (⚠️ worker pool needs initialization)
- ✅ **Reporting Engine** - Three built-in report types
- ✅ **JWT Authentication** - Secure session management with refresh tokens
- ✅ **Correlation IDs** - Request tracking across the system

### Security Features
- 🔐 Password hashing (bcrypt)
- 🔐 JWT-based authentication
- 🔐 **RBAC Authorization (Casbin)** - Role-based access control
- 🔐 Session management (in-memory)
- 🔐 CORS configuration
- 🔐 Security headers (CSP, Helmet)
- 🔐 SQL injection protection (parameterized queries)

### Analytics & Reporting
- 📊 Student Performance Analysis
- 📊 Classroom Engagement Metrics
- 📊 Content Effectiveness Evaluation
- 📊 Event-driven data collection
- 📊 Flexible JSONB metadata storage

## 🏗️ Architecture

### System Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Whiteboard App │         │   Notebook App  │
│   (Teacher)     │         │    (Student)    │
└────────┬────────┘         └────────┬────────┘
         │                           │
         │ REST API / WebSocket      │
         │                           │
         └───────────┬───────────────┘
                     │
         ┌───────────▼───────────┐
         │    API Server (Go)    │
         │  ┌─────────────────┐  │
         │  │  Controllers    │  │
         │  └─────────┬───────┘  │
         │  ┌─────────▼───────┐  │
         │  │  Repositories   │  │
         │  └─────────┬───────┘  │
         │  ┌─────────▼───────┐  │
         │  │   Event Queue   │  │
         │  │  (Worker Pool)  │  │
         │  └─────────────────┘  │
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │   PostgreSQL (DB)     │
         │  ┌─────────────────┐  │
         │  │ schools         │  │
         │  │ users           │  │
         │  │ classrooms      │  │
         │  │ quizzes         │  │
         │  │ questions       │  │
         │  │ responses       │  │
         │  │ events          │  │
         │  └─────────────────┘  │
         └───────────────────────┘
```

### Layer Architecture

```
┌──────────────────────────────────────────┐
│           API Layer (Gin)                │
│  - Routes, Middleware, WebSocket         │
└──────────────────┬───────────────────────┘
                   │
┌──────────────────▼───────────────────────┐
│        Controller Layer                  │
│  - Auth, Quiz, Response, Report, Events  │
└──────────────────┬───────────────────────┘
                   │
┌──────────────────▼───────────────────────┐
│        Service Layer                     │
│  - JWT, Session, Logger, Correlation     │
└──────────────────┬───────────────────────┘
                   │
┌──────────────────▼───────────────────────┐
│       Repository Layer                   │
│  - Users, Quizzes, Responses, Events     │
└──────────────────┬───────────────────────┘
                   │
┌──────────────────▼───────────────────────┐
│        Database Layer (GORM)             │
│  - PostgreSQL Connection & Queries       │
└──────────────────────────────────────────┘
```

### Event Processing Flow

```
API Request → Controller → Event Controller → Event Queue (Chan 5000)
                                                    │
                                   ┌────────────────┴────────────────┐
                                   │      Worker Pool (N workers)    │
                                   │  ┌────────┬────────┬────────┐   │
                                   │  │Worker 1│Worker 2│Worker 3│   │
                                   │  └───┬────┴───┬────┴───┬────┘   │
                                   └──────┼────────┼────────┼────────┘
                                          │        │        │
                                          ▼        ▼        ▼
                                      PostgreSQL Events Table
```

## 🛠️ Tech Stack

### Backend
- **Language:** Go 1.23+
- **Web Framework:** Gin
- **ORM:** GORM
- **Database:** PostgreSQL 14+
- **Authentication:** JWT (golang-jwt)
- **WebSocket:** Gorilla WebSocket
- **Logging:** Structured logging with correlation IDs (Uber Zap)
- **Containerization:** Docker & Docker Compose

### Libraries & Dependencies
```
github.com/gin-gonic/gin              # HTTP web framework
github.com/gin-contrib/cors           # CORS middleware
github.com/jinzhu/gorm                # ORM
github.com/lib/pq                     # PostgreSQL driver
github.com/golang-jwt/jwt             # JWT authentication
github.com/gorilla/websocket          # WebSocket support
github.com/casbin/casbin/v2           # RBAC authorization
github.com/danielkov/gin-helmet       # Security headers
github.com/google/uuid                # UUID generation for correlation IDs
go.uber.org/zap                       # Structured logging
gopkg.in/natefinch/lumberjack.v2      # Log rotation
golang.org/x/crypto                   # Password hashing (bcrypt)
github.com/caarlos0/env/v6            # Environment variable parsing
github.com/joho/godotenv              # .env file loading
bitbucket.org/liamstask/goose         # Database migrations
```

## 🚀 Getting Started

### Prerequisites

- **Go 1.23+** - [Install Go](https://golang.org/doc/install)
- **Docker & Docker Compose** - [Install Docker](https://docs.docker.com/get-docker/)
- **PostgreSQL 14+** (if running locally) - [Install PostgreSQL](https://www.postgresql.org/download/)
- **Make** (optional) - For using Makefile commands
- **Goose** - Database migration tool ([Install Goose](https://github.com/pressly/goose))

### Installation

#### Option 1: Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd eduanalytics
   ```

2. **Create environment file**
   ```bash
   cp .env_example .env
   # Edit .env with your configurations
   ```

3. **Start services**
   ```bash
   make start
   # OR
   docker-compose up --build -d
   ```

4. **Run database migrations**
   ```bash
   docker exec -it eduanalytics_app_1 sh
   cd internal/app/db/migrations
   goose postgres "host=postgres port=5432 user=postgres password=postgres dbname=eduanalytics sslmode=disable" up
   exit
   ```

5. **Access the API**
   ```
   http://localhost:9090/api/v1/
   ```

**⚠️ Note:** Event worker pool is not initialized by default. Events will be queued but not persisted to the database. To enable event persistence, you need to initialize the worker pool in `main.go` (see Known Issues section).

#### Option 2: Local Development

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd eduanalytics
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Setup PostgreSQL**
   ```bash
   # Start PostgreSQL (if using Docker)
   make db-start
   
   # OR create database manually
   createdb eduanalytics
   ```

4. **Create .env file**
   ```bash
   cp .env_example .env
   # Update DB_HOST to 'localhost' for local development
   ```

5. **Run migrations**
   ```bash
   cd internal/app/db/migrations
   goose postgres "host=localhost port=5432 user=postgres password=postgres dbname=eduanalytics sslmode=disable" up
   ```

6. **Setup RBAC (Casbin)**
   ```bash
   # Run the RBAC setup script
   ./setup_rbac.sh
   
   # Or manually install dependencies
   go mod tidy
   ```

7. **Run the application**
   ```bash
   go run main.go
   ```

### Environment Variables

Key environment variables in `.env`:

```bash
# Server
ENVIRONMENT=local
HTTPSERVER_PORT=9090
HTTPSERVER_LISTEN=0.0.0.0
HTTPSERVER_URL=http://localhost:9090

# Database
DB_HOST=postgres  # 'localhost' for local dev
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=eduanalytics
DB_LOGMODE=true
DB_MAX_OPEN_CONNECTION=25
DB_MAX_IDLE_CONNECTION=25
DB_CONNECTION_MAX_LIFETIME=300

# JWT
JWT_ACCESS_SECRET=your-access-secret
JWT_REFRESH_SECRET=your-refresh-secret
JWT_MAGIC_SECRET=your-magic-secret
JWT_ACCESS_EXP=300      # 5 minutes (in seconds)
JWT_REFRESH_EXP=600     # 10 minutes (in seconds)

# Logging
LOG_FILE_PATH=/tmp
LOG_FILE_NAME=eduanalytics.log
LOG_FILE_MAXSIZE=500    # MB
LOG_FILE_MAXBACKUP=3
LOG_FILE_MAXAGE=28      # days
```

## 📡 API Documentation

### Base URL
```
http://localhost:9090/api/v1
```

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@school.edu",
  "password": "securePassword123",
  "role": "student",
  "school_id": 1
}

Response: 202 Accepted
{
  "success": true,
  "message": "User Created Successfully",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@school.edu",
    "role": "student",
    "school_id": 1
  }
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@school.edu",
  "password": "securePassword123"
}

Response: 200 OK
{
  "success": true,
  "message": "Login Successfully",
  "data": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "at_expires": 1696681200,
    "rt_expires": 1696681500,
    "session_id": "a1b2c3d4..."
  }
}
```

#### Refresh Token
```http
POST /api/v1/auth/refresh
Authorization: Bearer <refresh_token>

Response: 200 OK
{
  "success": true,
  "message": "Token Refreshed Successfully",
  "data": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    ...
  }
}
```

#### Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer <access_token>

Response: 200 OK
{
  "success": true,
  "message": "Logout Successfully"
}
```

### Quiz Endpoints

#### Create Quiz
```http
POST /api/v1/quizzes
Content-Type: application/json

{
  "title": "Math Quiz - Chapter 5",
  "classroom_id": 10,
  "created_by": 5,
  "start_time": "2025-10-08T10:00:00Z",
  "end_time": "2025-10-08T11:00:00Z"
}

Response: 200 OK
{
  "success": true,
  "message": "Quiz created successfully",
  "data": {
    "id": 15,
    "title": "Math Quiz - Chapter 5",
    ...
  }
}
```

### Response Endpoints

#### Submit Response
```http
POST /api/v1/responses
Content-Type: application/json

{
  "student_id": 101,
  "question_id": 45,
  "answer": "B",
  "correct": true,
  "time_spent": 38.5
}

Response: 200 OK
{
  "success": true,
  "message": "Response recorded successfully",
  "data": { ... }
}
```

### Report Endpoints

#### Student Performance Report
```http
GET /api/v1/student-performance?student_id=101

Response: 200 OK
{
  "success": true,
  "message": "Student performance report",
  "data": {
    "student": "Alice Johnson",
    "attempts": 245,
    "correct": 198,
    "accuracy": 0.81
  }
}
```

#### Classroom Engagement Report
```http
GET /api/v1/classroom-engagement?classroom_id=10

Response: 200 OK
{
  "success": true,
  "message": "Classroom Engagement Report",
  "data": {
    "classroom": "Class 5A",
    "participants": 28,
    "avg_time": 42.3
  }
}
```

#### Content Effectiveness Report
```http
GET /api/v1/content-effectiveness?quiz_id=15

Response: 200 OK
{
  "success": true,
  "message": "Content Effectiveness Report",
  "data": {
    "reports": [
      {
        "question": "What is 2+2?",
        "attempts": 30,
        "correctness_rate": 0.97
      },
      {
        "question": "Solve: x² - 5x + 6 = 0",
        "attempts": 30,
        "correctness_rate": 0.63
      }
    ]
  }
}
```

### WebSocket Endpoint

#### Quiz WebSocket
```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:9090/api/v1/ws/quiz');

// Initial connection message
ws.send(JSON.stringify({
  user_id: 101,
  classroom_id: 10
}));

// Events from teacher (Whiteboard app)
{
  "event": "quiz_started",
  "quiz_id": 15,
  "classroom_id": 10,
  "user_id": 5
}

{
  "event": "question_displayed",
  "quiz_id": 15,
  "question_id": 45,
  "question_text": "What is 2+2?",
  "classroom_id": 10
}

// Event from student (Notebook app)
{
  "event": "answer_submitted",
  "user_id": 101,
  "quiz_id": 15,
  "question_id": 45,
  "answer": "B",
  "correct": true,
  "metadata": {
    "time_spent": 38.5
  }
}

// Teacher receives
{
  "event": "answer_received",
  "user_id": 101,
  ...
}
```

## 🗄️ Database Schema

### Tables Overview

| Table | Purpose | Records (Est.) |
|-------|---------|----------------|
| **schools** | School/institution data | ~1,000 |
| **users** | All user accounts | ~930,000 |
| **classrooms** | Classroom data | ~30,000 |
| **quizzes** | Quiz sessions | ~1.5M/year |
| **questions** | Quiz questions | ~15M/year |
| **responses** | Student answers | ~450M/year |
| **events** | Activity tracking | ~3.3B/year |

### Entity Relationships

See detailed [ER Diagram](docs/ER_DIAGRAM.md) for complete schema with relationships, indexes, and constraints.

### Key Relationships
- School → (1:N) → Users, Classrooms
- Teacher (User) → (1:N) → Classrooms, Quizzes
- Classroom → (1:N) → Quizzes
- Quiz → (1:N) → Questions
- Question → (1:N) → Responses
- Student (User) → (1:N) → Responses, Events

## 📊 Reports

### 1. Student Performance Analysis

**Purpose:** Track individual student progress and accuracy

**Metrics:**
- Total questions attempted
- Correct answers count
- Accuracy percentage
- (Future: Time-based trends, subject breakdown)

**SQL Query:**
```sql
SELECT u.name, 
       COUNT(r.id) as attempts,
       SUM(CASE WHEN r.correct THEN 1 ELSE 0 END) as correct,
       ROUND(SUM(CASE WHEN r.correct THEN 1 ELSE 0 END)::decimal / COUNT(r.id), 2) as accuracy
FROM responses r 
JOIN users u ON u.id = r.student_id
WHERE r.student_id = ?
GROUP BY u.name;
```

### 2. Classroom Engagement Metrics

**Purpose:** Measure classroom participation and activity

**Metrics:**
- Unique participant count
- Average time spent per question
- (Future: Engagement rate, active vs passive students)

**SQL Query:**
```sql
SELECT c.name, 
       COUNT(DISTINCT r.student_id) as participants,
       AVG(r.time_spent) as avg_time
FROM responses r
JOIN questions q ON q.id = r.question_id
JOIN quizzes z ON q.quiz_id = z.id
JOIN classrooms c ON z.classroom_id = c.id
WHERE c.id = ?
GROUP BY c.name;
```

### 3. Content Effectiveness Evaluation

**Purpose:** Identify difficult questions and optimize content

**Metrics:**
- Per-question attempt counts
- Correctness rates
- (Future: Common wrong answers, difficulty classification)

**SQL Query:**
```sql
SELECT q.question_text,
       COUNT(r.id) as attempts,
       ROUND(SUM(CASE WHEN r.correct THEN 1 ELSE 0 END)::decimal / COUNT(r.id), 2) as correctness_rate
FROM responses r 
JOIN questions q ON q.id = r.question_id
WHERE q.quiz_id = ?
GROUP BY q.question_text;
```

## 📈 Event Tracking

### Event Types

| Event | Source App | Triggered By | Purpose |
|-------|------------|--------------|---------|
| `quiz_created` | Whiteboard | Teacher | Track quiz creation |
| `quiz_started` | Whiteboard | Teacher | Mark quiz start time |
| `question_displayed` | Whiteboard | Teacher | Track question visibility |
| `answer_submitted` | Notebook | Student | Track student responses |
| `quiz_ended` | Whiteboard | Teacher | Mark quiz completion |

### Event Schema
```json
{
  "id": 1,
  "event_name": "question_submitted",
  "app": "notebook",
  "user_id": 101,
  "quiz_id": 15,
  "classroom_id": 10,
  "metadata": {
    "question_id": 45,
    "answer": "B",
    "correct": true,
    "time_spent": 38.5
  },
  "timestamp": "2025-10-07T14:32:10Z"
}
```

### Event Processing
- **Queue:** Buffered channel with 5,000 capacity
- **Workers:** Configurable worker pool (⚠️ Currently not started - needs initialization in main.go)
- **Processing:** Asynchronous, non-blocking (when worker pool is active)
- **Storage:** PostgreSQL events table
- **⚠️ Note:** Events are queued but not persisted until worker pool is initialized

## 🚢 Deployment

### Docker Deployment

```bash
# Build and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f app

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down --volumes
```

### Production Considerations

**⚠️ IMPORTANT: This application is NOT production-ready in its current state.**

**Critical items that MUST be addressed:**

1. **Initialize Event Worker Pool:**
   - [ ] Add `eventsController.StartWorkerPool(ctx, numWorkers)` in main.go
   - [ ] Without this, events are queued but never persisted to database

2. **Security:**
   - [ ] Change all default passwords and secrets
   - [ ] Use environment-specific `.env` files (don't commit!)
   - [ ] Enable HTTPS/TLS
   - [ ] Implement rate limiting
   - [ ] Add comprehensive input validation
   - [x] Enable RBAC authorization (✅ Implemented with Casbin)
   - [ ] Add authentication to WebSocket endpoint
   - [ ] Implement API key or token validation

3. **Scalability:**
   - [ ] Replace in-memory session storage with Redis
   - [ ] Use persistent message queue (RabbitMQ/Kafka) instead of in-memory channel
   - [ ] Optimize database connection pooling
   - [ ] Add database read replicas for reports
   - [ ] Implement table partitioning for events and responses tables
   - [ ] Add query result caching layer

4. **Monitoring & Observability:**
   - [ ] Add health check endpoint (`/health`)
   - [ ] Add Prometheus metrics
   - [ ] Setup Grafana dashboards
   - [ ] Implement distributed tracing (Jaeger/Zipkin)
   - [ ] Add error tracking (Sentry)
   - [ ] Add application performance monitoring

5. **Data Management:**
   - [ ] Setup automated database backups
   - [ ] Implement data archival strategy (events/responses older than X months)
   - [ ] Add database indexes for performance (already has basic indexes)
   - [ ] Setup query result caching
   - [ ] Implement data retention policies

6. **Error Handling & Resilience:**
   - [ ] Implement graceful shutdown
   - [ ] Add circuit breakers for external dependencies
   - [ ] Improve error responses with proper error codes
   - [ ] Add retry logic for failed operations
   - [ ] Implement request timeout handling

### Environment-Specific Configs

**Development:**
- Debug logging enabled
- CORS: Allow all origins
- DB_LOGMODE: true

**Staging:**
- Info-level logging
- CORS: Specific origins
- DB_LOGMODE: false

**Production:**
- Error-level logging only
- CORS: Whitelist only
- DB_LOGMODE: false
- Enable all security features

## 👨‍💻 Development

### Project Structure

```
eduanalytics/
├── main.go                          # Application entry point
├── go.mod / go.sum                  # Go dependencies
├── Dockerfile                       # Docker image definition
├── docker-compose.yml               # Multi-container setup
├── Makefile                         # Build commands
├── .env_example                     # Environment template
├── README.md                        # This file
├── configs/                        # Configuration files
│   ├── casbin_model.conf          # Casbin RBAC model
│   └── casbin_policy.csv          # Casbin permission policies
├── docs/                            # Documentation
│   ├── ER_DIAGRAM.md               # Database schema
│   ├── SEQUENCE_DIAGRAMS.md        # Flow diagrams
│   ├── TECHNICAL_DESIGN_DOCUMENT.md # Technical design
│   ├── RBAC_IMPLEMENTATION.md      # RBAC documentation
│   └── README.md                   # Documentation README
├── internal/
│   ├── config/
│   │   └── config.go               # Configuration loader
│   └── app/
│       ├── api/
│       │   ├── middleware/         # Auth, JWT, Casbin middleware
│       │   └── server/             # Router, routes
│       ├── constants/              # App constants
│       ├── controller/             # Request handlers
│       │   ├── auth.go
│       │   ├── quzzies.go
│       │   ├── response.go
│       │   ├── report.go
│       │   ├── events/
│       │   └── ws/
│       ├── db/
│       │   ├── db.go               # DB connection
│       │   ├── dto/                # Data models
│       │   ├── migrations/         # SQL migrations
│       │   └── repository/         # Data access layer
│       └── service/
│           ├── correlation/        # Request correlation
│           ├── dto/                # Service DTOs
│           ├── logger/             # Logging service
│           ├── session/            # Session management
│           └── util/               # Utilities
```

### Makefile Commands

```bash
# Start all services (Docker)
make start

# Stop all services
make down

# Start only PostgreSQL
make db-start

# Run linter
make lint

# Create new migration
make migration
# Then enter migration name
```

### Adding New Features

1. **Add a new endpoint:**
   - Define route in `internal/app/api/server/routes.go`
   - Create controller method in appropriate controller file
   - Add repository method for data access
   - Update API documentation

2. **Add a new report:**
   - Add SQL query in `internal/app/db/repository/report.go`
   - Create controller method in `internal/app/controller/report.go`
   - Add route in `router.go`
   - Document in README

3. **Add a new event type:**
   - Define event name constant
   - Trigger event in appropriate controller
   - Event automatically processed by worker pool

### Database Migrations

Using [Goose](https://github.com/pressly/goose):

```bash
# Create new migration
cd internal/app/db/migrations
goose create add_user_status sql

# Run migrations
goose postgres "connection-string" up

# Rollback last migration
goose postgres "connection-string" down
```

## 🧪 Testing

### Manual Testing

#### Test Authentication Flow
```bash
# Register user
curl -X POST http://localhost:9090/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@test.com","password":"test123","role":"student","school_id":1}'

# Login
curl -X POST http://localhost:9090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'

# Save the access_token from response
export TOKEN="<access_token>"

# Make authenticated request
curl -X POST http://localhost:9090/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

#### Test Quiz Flow
```bash
# Create quiz
curl -X POST http://localhost:9090/api/v1/quizzes \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Quiz","classroom_id":1,"created_by":1,"start_time":"2025-10-08T10:00:00Z","end_time":"2025-10-08T11:00:00Z"}'

# Submit response
curl -X POST http://localhost:9090/api/v1/responses \
  -H "Content-Type: application/json" \
  -d '{"student_id":1,"question_id":1,"answer":"B","correct":true,"time_spent":30.5}'
```

#### Test Reports
```bash
# Student performance
curl http://localhost:9090/api/v1/student-performance?student_id=1

# Classroom engagement
curl http://localhost:9090/api/v1/classroom-engagement?classroom_id=1

# Content effectiveness
curl http://localhost:9090/api/v1/content-effectiveness?quiz_id=1
```

### Future: Automated Tests

**TODO: Implement**
- [ ] Unit tests for repositories
- [ ] Integration tests for API endpoints
- [ ] Load tests for scale validation
- [ ] E2E tests for critical flows

## ⚙️ Current Implementation Status

### ✅ Completed Features
- User registration and authentication
- JWT-based session management with refresh tokens
- **RBAC Authorization (Casbin)** - Role-based access control for admin/teacher/student
- Quiz creation endpoint
- Response submission endpoint
- Three reporting endpoints (Student Performance, Classroom Engagement, Content Effectiveness)
- WebSocket real-time quiz synchronization
- Event queue system (buffered channel)
- Database schema with migrations
- Request correlation ID tracking
- Structured logging with Zap
- Security headers (Helmet, CORS, CSP)
- Docker containerization

### ⚠️ Incomplete/Needs Work
- **Event Worker Pool** - Defined but not started (critical for event persistence)
- **Input Validation** - Basic or missing on most endpoints
- **Error Handling** - Could be more comprehensive
- **WebSocket Auth** - No authentication on WebSocket connections
- **Health Checks** - No health check endpoint for monitoring
- **Graceful Shutdown** - Not implemented
- **Tests** - No unit or integration tests

### 🔧 Configuration Required
Before running, you need to:
1. Create a `.env` file (see Environment Variables section)
2. Set up PostgreSQL database
3. Run database migrations using Goose
4. Configure JWT secrets (don't use defaults in production!)

## 🐛 Known Issues & Limitations

### Critical Issues (Must Fix Before Production)

#### 1. ⚠️ Event Worker Pool Not Started
**Problem:** Worker pool is defined but never initialized in main.go. Events are queued but never persisted to database.

**Fix:** Add the following code to `main.go` after initializing the router:
```go
// In main.go, after r := server.Init(ctx)
eventsController := events.NewEventsController(eventsRepository)
eventsController.StartWorkerPool(ctx, 5) // Start with 5 workers
```

Note: This requires refactoring `server.Init()` to return the events controller or initializing it in main.go instead.

#### 2. ✅ RBAC Authorization Implemented
Role-based access control using Casbin is now implemented. See `QUICK_START_RBAC.md` for details.

#### 3. ⚠️ In-Memory Session Storage
Sessions are lost on restart. Should use Redis or similar for production.

#### 4. ⚠️ WebSocket Error Handling
Limited error handling in WebSocket connections. Need better error recovery.

#### 5. ⚠️ No Request Validation
Missing comprehensive input validation on API requests.

### Limitations
- Event worker pool not initialized (events queued but not persisted)
- No pagination on reports (can return large datasets)
- Limited input validation on request bodies
- No rate limiting on API endpoints
- No caching for reports
- Event queue is in-memory (not persistent across restarts)
- No batch import endpoints
- No data export functionality (CSV/PDF)
- Reports lack date range filtering
- WebSocket connections lack authentication
- No health check endpoint for monitoring

### Scalability Concerns
- In-memory session store (cannot scale horizontally without sticky sessions)
- In-memory event queue (not durable, events lost on crash/restart)
- WebSocket connections tied to single server (cannot load balance easily)
- Events table will grow rapidly (needs partitioning strategy)
- No query result caching (repeated queries hit database)
- No connection pooling optimization
- Responses table will grow very large (~450M/year) without archival strategy

## 🗺️ Roadmap

### Phase 1: Critical Fixes (Immediate)
- [ ] Start event worker pool in main.go initialization
- [x] Implement RBAC authorization (✅ Completed with Casbin)
- [ ] Add comprehensive input validation
- [ ] Improve WebSocket error handling
- [ ] Add graceful shutdown handling

### Phase 2: Production Readiness (Short-term)
- [ ] Replace in-memory sessions with Redis
- [ ] Add persistent message queue (RabbitMQ)
- [ ] Implement table partitioning
- [ ] Add database indexes
- [ ] Add API documentation (Swagger)
- [ ] Implement caching layer
- [ ] Add pagination to reports

### Phase 3: Feature Enhancement (Medium-term)
- [ ] Generic query framework (Cube.dev)
- [ ] Advanced analytics and visualizations
- [ ] Data export (CSV, PDF)
- [ ] Batch import endpoints
- [ ] Email report scheduling
- [ ] Materialized views for reports
- [ ] Time-range filtering for reports

### Phase 4: Advanced Features (Long-term)
- [ ] Machine learning for predictions
- [ ] Recommendation engine
- [ ] Multi-language support
- [ ] Mobile SDK
- [ ] GraphQL API
- [ ] Real-time dashboards

## 📚 Documentation

- **[ER Diagram](docs/ER_DIAGRAM.md)** - Complete database schema with relationships
- **[Sequence Diagrams](docs/SEQUENCE_DIAGRAMS.md)** - 6 key workflow diagrams
- **[Technical Design Document](docs/TECHNICAL_DESIGN_DOCUMENT.md)** - Detailed technical design and architecture
- **[RBAC Implementation](docs/RBAC_IMPLEMENTATION.md)** - Complete RBAC documentation
- **[Quick Start RBAC](QUICK_START_RBAC.md)** - Quick setup guide for RBAC
- **[RBAC Summary](RBAC_IMPLEMENTATION_SUMMARY.md)** - Implementation summary
- **[Documentation README](docs/README.md)** - Documentation overview

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Guidelines
- Follow Go best practices and idioms
- Write meaningful commit messages
- Add comments for complex logic
- Update documentation for new features
- Write tests for new functionality

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Shubham Agarwal** - *Initial work* - shubham@orgosys.com

## 🙏 Acknowledgments

- Task provided by EduAnalytics Team
- Built as part of Backend Engineering Assessment
- Inspired by modern educational platforms

## 📞 Support

For support, email shubham@orgosys.com or open an issue in the repository.

## 📊 Project Statistics

- **Language:** Go 1.23
- **Lines of Code:** ~2,500+
- **Files:** 30+
- **API Endpoints:** 8 REST + 1 WebSocket
- **Database Tables:** 7
- **Report Types:** 3
- **Middleware:** 5+ (Auth, JWT, CORS, Helmet, UUID injection)
- **Controllers:** 5 (Auth, Quiz, Response, Report, Events, WebSocket)

---

**Last Updated:** October 7, 2025  
**Version:** 1.0.0  
**Status:** Development (Not Production Ready)

---

<div align="center">

### ⭐ Star this repo if you find it helpful!

Made with ❤️ for educational analytics

</div>


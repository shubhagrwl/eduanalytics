# Technical Design Document
## EduAnalytics - Educational Reporting Framework

**Version:** 1.0  
**Date:** October 7, 2025  
**Author:** Shubham Agarwal  
**Status:** Implementation Complete

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Data Collection Strategy](#3-data-collection-strategy)
4. [Database Design](#4-database-design)
5. [API Design](#5-api-design)
6. [Architecture & Design Patterns](#6-architecture--design-patterns)
7. [Security Considerations](#7-security-considerations)
8. [Scalability & Performance](#8-scalability--performance)
9. [Technology Stack](#9-technology-stack)
10. [Deployment Strategy](#10-deployment-strategy)
11. [Monitoring & Observability](#11-monitoring--observability)
12. [Assumptions & Constraints](#12-assumptions--constraints)
13. [Alternative Approaches Considered](#13-alternative-approaches-considered)
14. [Future Enhancements](#14-future-enhancements)

---

## 1. Executive Summary

### 1.1 Problem Statement

Educational institutions need a comprehensive reporting and analytics system that can:
- Track student interactions across multiple applications (Whiteboard for teachers, Notebook for students)
- Provide real-time synchronization for quiz sessions
- Generate actionable insights on student performance, classroom engagement, and content effectiveness
- Scale to handle 1,000 schools with 30 classrooms each and 30 students per classroom (~900,000 students)

### 1.2 Solution Overview

EduAnalytics is a backend reporting framework that:
- Captures events from both Whiteboard (teacher) and Notebook (student) applications
- Stores structured data in PostgreSQL with optimized schema
- Processes events asynchronously using worker pools
- Provides REST APIs for data ingestion and report generation
- Supports real-time quiz sessions via WebSocket
- Implements JWT-based authentication and session management

### 1.3 Key Features Delivered

✅ **Data Ingestion:** REST API endpoints for quiz creation and response submission  
✅ **Event Tracking:** Asynchronous event processing with worker pool (5,000 event buffer)  
✅ **Real-time Sync:** WebSocket support for live quiz sessions  
✅ **Reporting Engine:** Three built-in reports:
   - Student Performance Analysis
   - Classroom Engagement Metrics
   - Content Effectiveness Evaluation  
✅ **Authentication:** JWT-based auth with session management  
✅ **Scalable Architecture:** Event-driven design with repository pattern

### 1.4 Success Metrics

- **Scalability:** Handle 900,000 students, 3.3B events/year
- **Performance:** <100ms API response time, <50ms WebSocket latency
- **Reliability:** 99.9% uptime, zero data loss
- **Security:** All endpoints authenticated, passwords hashed, SQL injection protected

---

## 2. System Overview

### 2.1 High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Client Applications                     │
│  ┌─────────────────────┐    ┌─────────────────────┐       │
│  │  Whiteboard App     │    │   Notebook App      │       │
│  │  (Teachers)         │    │   (Students)        │       │
│  └──────────┬──────────┘    └──────────┬──────────┘       │
│             │                           │                   │
└─────────────┼───────────────────────────┼───────────────────┘
              │                           │
              │    REST API / WebSocket   │
              │                           │
┌─────────────▼───────────────────────────▼───────────────────┐
│                    API Gateway Layer                        │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Gin Router (CORS, Security Headers, Middleware)  │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Business Logic Layer                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Auth   │  │   Quiz   │  │ Response │  │  Report  │   │
│  │Controller│  │Controller│  │Controller│  │Controller│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │               │             │         │
│  ┌────▼──────────────▼───────────────▼─────────────▼─────┐ │
│  │            Event Processing Layer                     │ │
│  │  ┌──────────────────────────────────────────────┐    │ │
│  │  │   Events Controller → Queue → Worker Pool    │    │ │
│  │  └──────────────────────────────────────────────┘    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Data Access Layer                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Repository Pattern (Users, Quizzes, Responses,   │    │
│  │  Events, Reports)                                  │    │
│  └──────────────────────────┬─────────────────────────┘    │
└─────────────────────────────┼───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                   Persistence Layer                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │         PostgreSQL (7 tables, JSONB metadata)     │    │
│  │  schools | users | classrooms | quizzes |         │    │
│  │  questions | responses | events                    │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Interaction Flow

**Quiz Creation Flow:**
1. Teacher creates quiz via Whiteboard App → POST /api/v1/quizzes
2. API Gateway validates JWT token
3. Quiz Controller stores quiz in database
4. Event Controller publishes "quiz_created" event to queue
5. Worker pool asynchronously stores event
6. Response returned to teacher

**Student Response Flow:**
1. Student submits answer via Notebook App → POST /api/v1/responses
2. Response Controller stores response (synchronous - critical)
3. Event Controller publishes "question_submitted" event (asynchronous - analytics)
4. Response confirmation returned to student

**Report Generation Flow:**
1. Teacher requests report → GET /api/v1/student-performance?student_id=X
2. Report Controller queries aggregated data from database
3. SQL aggregation performed (COUNT, AVG, SUM)
4. Formatted report returned to teacher

### 2.3 Communication Protocols

**REST API:**
- JSON request/response
- HTTP/HTTPS
- Stateless (JWT in Authorization header)
- Used for: CRUD operations, reports

**WebSocket:**
- Persistent bidirectional connection
- Message-based protocol (JSON)
- Stateful (connection per user)
- Used for: Real-time quiz sessions

---

## 3. Data Collection Strategy

### 3.1 Objectives

1. **Comprehensive Tracking:** Capture all user interactions across both applications
2. **Real-time Analytics:** Enable instant insights without batch processing delays
3. **Privacy Compliance:** Track only necessary data, anonymize where possible
4. **Performance:** Non-blocking event capture, asynchronous processing
5. **Flexibility:** JSONB metadata for evolving event schemas

### 3.2 Event-Based Tracking Methodology

**Event-Driven Architecture:**
- All significant user actions trigger events
- Events are queued and processed asynchronously
- Business logic doesn't wait for event storage (performance)
- Events stored in PostgreSQL for permanent record

**Event Taxonomy:**

| Event Name | Source App | Triggered By | Metadata |
|------------|------------|--------------|----------|
| `quiz_created` | Whiteboard | Teacher creates quiz | quiz_id, classroom_id |
| `quiz_started` | Whiteboard | Teacher starts session | quiz_id, start_time |
| `question_displayed` | Whiteboard | Teacher displays question | question_id, display_time |
| `answer_submitted` | Notebook | Student submits answer | question_id, answer, correct, time_spent |
| `quiz_ended` | Whiteboard | Teacher ends quiz | quiz_id, end_time |

**Future Event Types (Recommended):**
- `student_login` / `student_logout`
- `classroom_joined` / `classroom_left`
- `content_viewed` (for non-quiz content)
- `help_requested` (student needs assistance)
- `app_error` (error tracking)

### 3.3 Metrics Tracked

**Student-Level Metrics:**
- Response correctness (boolean)
- Time spent per question (seconds)
- Total questions attempted
- Accuracy rate (correct/total)
- Participation frequency
- Session duration

**Classroom-Level Metrics:**
- Active participants count
- Average time per question
- Engagement rate (participants/enrolled)
- Quiz completion rate

**Content-Level Metrics:**
- Question difficulty (inferred from correctness rate)
- Common incorrect answers (via metadata analysis)
- Average attempts per question
- Time distribution per question

### 3.4 Data Flow Diagram

```
User Action (Whiteboard/Notebook)
        │
        ▼
Controller Handles Request
        │
        ├─────────────────────┐
        │                     │
        ▼                     ▼
   Primary Action      Publish Event
   (Synchronous)       (Asynchronous)
   - Quiz Create            │
   - Response Save          ▼
        │              Event Queue
        │              (Chan 5000)
        │                   │
        ▼                   ▼
   Return to User     Worker Pool
   (Fast Response)    (Background)
                           │
                           ▼
                      Store in DB
                      (events table)
                           │
                           ▼
                    Available for
                    Analytics/Reports
```

### 3.5 Event Schema Design

**Event Table Structure:**
```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_name VARCHAR(100) NOT NULL,     -- Event type
    app VARCHAR(50),                      -- Source: 'whiteboard' or 'notebook'
    user_id INT REFERENCES users(id),     -- Who triggered it
    quiz_id INT,                          -- Related quiz (nullable)
    classroom_id INT,                     -- Related classroom (nullable)
    metadata JSONB,                       -- Flexible data
    timestamp TIMESTAMP DEFAULT NOW()     -- When it happened
);
```

**Example Event Records:**
```json
{
  "id": 1001,
  "event_name": "quiz_created",
  "app": "whiteboard",
  "user_id": 5,
  "quiz_id": 15,
  "classroom_id": 10,
  "metadata": {
    "title": "Math Quiz - Chapter 5",
    "question_count": 10
  },
  "timestamp": "2025-10-07T10:00:00Z"
}

{
  "id": 1002,
  "event_name": "question_submitted",
  "app": "notebook",
  "user_id": 101,
  "quiz_id": 15,
  "classroom_id": 10,
  "metadata": {
    "question_id": 45,
    "answer": "B",
    "correct": true,
    "time_spent": 38.5,
    "attempt_number": 1
  },
  "timestamp": "2025-10-07T10:05:23Z"
}
```

### 3.6 Data Quality & Validation

**Validation Rules:**
1. Event name must be from predefined list (prevents typos)
2. User ID must exist in users table
3. Timestamp auto-generated (prevents client clock issues)
4. Metadata validated based on event type
5. Required fields enforced at application level

**Data Retention Policy:**
- Hot data: Last 13 months (in main table)
- Warm data: 14-36 months (in archive table)
- Cold data: >36 months (compressed, object storage)

---

## 4. Database Design

### 4.1 Schema Design Principles

1. **Normalization:** 3NF to eliminate redundancy
2. **Performance:** Strategic denormalization for read-heavy reports
3. **Scalability:** Partitioning strategy for large tables
4. **Flexibility:** JSONB for evolving schemas
5. **Integrity:** Foreign keys and constraints for data consistency

### 4.2 Entity-Relationship Model

See [ER Diagram](ER_DIAGRAM.md) for complete visual representation.

**Core Entities:**
- **schools** - Educational institutions
- **users** - Students, teachers, admins
- **classrooms** - Teaching groups
- **quizzes** - Quiz sessions
- **questions** - Quiz questions
- **responses** - Student answers
- **events** - Activity logs

### 4.3 Table Specifications

#### 4.3.1 Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password TEXT NOT NULL,                    -- bcrypt hashed
    role VARCHAR(20) CHECK (role IN ('admin', 'teacher', 'student')),
    school_id INT REFERENCES schools(id),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_user_role ON users(role);
CREATE INDEX idx_user_email ON users(email);
```

**Design Decisions:**
- Email as natural unique identifier
- Role-based for RBAC (future)
- Password stored as bcrypt hash (cost factor 10)
- School relationship for multi-tenancy

#### 4.3.2 Responses Table
```sql
CREATE TABLE responses (
    id SERIAL PRIMARY KEY,
    student_id INT REFERENCES users(id),
    question_id INT REFERENCES questions(id),
    answer VARCHAR(10),
    correct BOOLEAN,
    time_spent FLOAT,                          -- Seconds
    submitted_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_responses_student ON responses(student_id);
CREATE INDEX idx_responses_question ON responses(question_id);
CREATE INDEX idx_responses_submitted_at ON responses(submitted_at);
```

**Design Decisions:**
- Time stored as FLOAT (⚠️ precision loss possible, consider INTERVAL)
- Correctness pre-computed (denormalization for query speed)
- Indexes on foreign keys for JOIN performance
- Temporal index for time-series analysis

#### 4.3.3 Events Table
```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_name VARCHAR(100) NOT NULL,
    app VARCHAR(50),
    user_id INT REFERENCES users(id),
    quiz_id INT,                               -- No FK constraint (soft delete)
    classroom_id INT,                          -- No FK constraint
    metadata JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_event_type ON events(event_name);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_quiz ON events(quiz_id);
```

**Design Decisions:**
- JSONB for flexible metadata (schemaless)
- No FK on quiz_id/classroom_id (events persist after deletion)
- Timestamp indexed for time-range queries
- Will grow to billions of records → partition strategy required

### 4.4 Indexing Strategy

**Purpose:** Optimize query performance for reporting

**Indexes Created:**
1. **Primary Keys:** Auto-indexed (all tables)
2. **Foreign Keys:** Manually indexed for JOIN performance
3. **Query Columns:** Indexed based on WHERE/GROUP BY usage
4. **Temporal:** Timestamp indexes for time-series queries

**Index Cost-Benefit:**
- ✅ Faster SELECT queries (reports)
- ❌ Slower INSERT/UPDATE (acceptable for read-heavy workload)
- ❌ Additional storage (~10-15% of table size)

### 4.5 Data Growth Projections

See [ER Diagram - Storage Estimates](ER_DIAGRAM.md#storage-estimates) for detailed calculations.

**Year 1 Estimates:**
- Total Records: ~3.8 billion
- Total Storage: ~996 GB
- Events Table: ~945 GB (95% of total)

**Scalability Strategies:**
1. **Table Partitioning** (Events, Responses)
   - Partition by month (12 partitions/year)
   - Automatic partition creation
   - Drop old partitions after archival

2. **Materialized Views** (Reports)
   - Pre-aggregate common queries
   - Refresh hourly/daily
   - Reduce query time from seconds to milliseconds

3. **Archival Strategy**
   - Move data >13 months to archive schema
   - Compress using pg_compress
   - Store in cheaper storage tier

---

## 5. API Design

### 5.1 RESTful Principles

**Design Philosophy:**
- Resource-based URLs (nouns, not verbs)
- HTTP methods for actions (GET, POST, PUT, DELETE)
- Stateless requests (JWT in header)
- JSON request/response
- Consistent error formats
- Versioned API (v1)

### 5.2 Endpoint Catalog

**Base URL:** `http://localhost:9090/api/v1`

#### 5.2.1 Authentication Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/auth/register` | No | Create new user account |
| POST | `/auth/login` | No | Login and get tokens |
| POST | `/api/v1/auth/refresh` | Yes (Refresh) | Get new access token |
| POST | `/api/v1/auth/logout` | Yes (Access) | Invalidate session |

#### 5.2.2 Quiz Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/v1/quizzes` | ⚠️ No (Should be Yes) | Create quiz |

**⚠️ Issue:** Missing authentication and authorization!

#### 5.2.3 Response Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/api/v1/responses` | ⚠️ No (Should be Yes) | Submit student answer |

**⚠️ Issue:** No validation of student_id vs authenticated user!

#### 5.2.4 Report Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/v1/student-performance?student_id={id}` | ⚠️ No | Student performance report |
| GET | `/api/v1/classroom-engagement?classroom_id={id}` | ⚠️ No | Classroom engagement report |
| GET | `/api/v1/content-effectiveness?quiz_id={id}` | ⚠️ No | Content effectiveness report |

**⚠️ Critical Issues:**
1. No authentication (anyone can access)
2. No authorization (can access any student's data)
3. No pagination (could return millions of records)
4. No filtering (date range, subject, etc.)

### 5.3 Request/Response Schemas

See [README - API Documentation](../README.md#-api-documentation) for complete schemas.

**Standard Response Format:**
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { ... }
}
```

**Error Response Format:**
```json
{
  "success": false,
  "message": "Error description",
  "data": null
}
```

### 5.4 Authentication & Authorization

**Current Implementation:**
- ✅ JWT-based authentication
- ✅ Access token (5 min expiry)
- ✅ Refresh token (10 min expiry)
- ✅ Session management (in-memory)
- ❌ **No RBAC enforcement**
- ❌ **Missing auth on key endpoints**

**How It Should Work:**

```go
// Middleware chain
api.Use(auth.Authentication(jwtService))          // Verify JWT
api.Use(auth.Authorization("teacher", "admin"))   // Check role
api.GET("/student-performance", reportController.StudentPerformanceReport)
```

**Authorization Rules:**
- Teachers: Can access their classroom's data
- Students: Can access only their own data
- Admins: Can access all data

### 5.5 WebSocket Protocol

**Endpoint:** `ws://localhost:9090/ws/quiz`

**Connection Flow:**
1. Client connects with initial message:
   ```json
   { "user_id": 101, "classroom_id": 10 }
   ```
2. Server adds to classroom broadcast group
3. Client can send/receive events

**Message Types:**

**Teacher → Students:**
```json
{ "event": "quiz_started", "quiz_id": 15, "classroom_id": 10 }
{ "event": "question_displayed", "question_id": 45, "question_text": "..." }
{ "event": "quiz_ended", "quiz_id": 15 }
```

**Student → Teacher:**
```json
{
  "event": "answer_submitted",
  "user_id": 101,
  "question_id": 45,
  "answer": "B",
  "correct": true,
  "metadata": { "time_spent": 38.5 }
}
```

**⚠️ Issue:** No authentication on WebSocket connection!

### 5.6 Rate Limiting (Not Implemented)

**Recommended:**
- 100 requests/minute per user (normal operations)
- 10 requests/minute for reports (expensive queries)
- 1000 events/minute (bulk event ingestion)

---

## 6. Architecture & Design Patterns

### 6.1 Architectural Style: Layered Architecture

**Layers:**
1. **API Layer** - HTTP routing, middleware, WebSocket
2. **Controller Layer** - Request handling, response formatting
3. **Service Layer** - Business logic, cross-cutting concerns
4. **Repository Layer** - Data access abstraction
5. **Database Layer** - Persistence

**Benefits:**
- ✅ Separation of concerns
- ✅ Testability (can mock layers)
- ✅ Maintainability
- ✅ Technology independence

### 6.2 Design Patterns Used

#### 6.2.1 Repository Pattern
```go
type IUsersRepository interface {
    CreateUser(ctx context.Context, user *dto.User) error
    GetUser(ctx context.Context, where string) (*dto.User, error)
    GetUserByEmail(ctx context.Context, email string) (*dto.User, error)
}
```

**Benefits:**
- Abstract data access logic
- Easy to switch databases
- Simplifies testing (mock repositories)

#### 6.2.2 Dependency Injection
```go
func NewReportController(
    dbClient repository.IReportsRepository,
    eventsController events.IEventsController,
) IReportController {
    return &ReportController{
        DBClient: dbClient,
        EventsController: eventsController,
    }
}
```

**Benefits:**
- Loose coupling
- Easier testing
- Runtime flexibility

#### 6.2.3 Worker Pool Pattern
```go
func (e *EventsController) StartWorkerPool(ctx context.Context, workers int) {
    for i := 0; i < workers; i++ {
        go func(id int) {
            for event := range EventQueue {
                // Process event
                e.DBClient.CreateEvent(ctx, &event)
            }
        }(i)
    }
}
```

**Benefits:**
- Concurrent processing
- Controlled resource usage
- Non-blocking event handling

#### 6.2.4 Middleware Chain
```go
router.Use(gin.Logger())
router.Use(gin.Recovery())
router.Use(helmet.Default())
router.Use(cors.New(corsConfig))
router.Use(uuidInjectionMiddleware())
```

**Benefits:**
- Cross-cutting concerns (logging, auth, CORS)
- Request/response transformation
- Error handling

### 6.3 Asynchronous Event Processing

**Architecture:**
```
API Request → Controller
                │
                ├─ Synchronous: Save critical data (quiz, response)
                │  └─ Return fast response to user
                │
                └─ Asynchronous: Publish event
                   └─ Event Queue (buffered channel, 5000 cap)
                      └─ Worker Pool (N goroutines)
                         └─ Store in events table
```

**Configuration:**
- Queue Capacity: 5,000 events
- Worker Count: Configurable (recommend: num_cpu * 2)
- Overflow Behavior: Blocks (⚠️ should implement backpressure)

**Trade-offs:**
- ✅ Fast API responses (non-blocking)
- ✅ Decoupled analytics from business logic
- ❌ Event loss if server crashes (in-memory queue)
- ❌ No retry mechanism for failures

### 6.4 Session Management

**Implementation:** In-Memory Map
```go
type SessionManager struct {
    sessions      map[string]*Session      // sessionID → Session
    userSessions  map[string][]string      // email → [sessionIDs]
    mu            sync.RWMutex
    sessionExpiry time.Duration
}
```

**Features:**
- 24-hour session expiry
- Background cleanup (every 15 min)
- Multi-session support per user
- Thread-safe (mutex protected)

**Limitations:**
- ❌ Lost on restart (not persistent)
- ❌ Cannot scale horizontally
- ❌ No distributed session sharing

**Recommended Fix:** Use Redis for session storage

---

## 7. Security Considerations

### 7.1 Authentication Mechanisms

**JWT (JSON Web Tokens):**
- Access Token: Short-lived (5 min), for API requests
- Refresh Token: Longer-lived (10 min), for token renewal
- HMAC-SHA256 signature
- Claims: email, session_id, exp

**Token Flow:**
1. Login → Receive access + refresh tokens
2. API request → Send access token in `Authorization: Bearer <token>` header
3. Token expires → Use refresh token to get new pair
4. Logout → Invalidate session (tokens become useless)

### 7.2 Password Security

```go
// Hashing (registration)
hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

// Validation (login)
err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
```

**Security Features:**
- bcrypt with cost factor 10 (2^10 rounds)
- Salted hashes (automatic with bcrypt)
- Constant-time comparison

### 7.3 SQL Injection Prevention

**Parameterized Queries:**
```go
// Safe (parameterized)
db.Where("email = ?", email).First(&user)

// Unsafe (don't do this!)
db.Where(fmt.Sprintf("email = '%s'", email)).First(&user)
```

All queries use GORM which auto-parameterizes.

### 7.4 CORS & Security Headers

```go
// CORS configuration
cors.New(cors.Config{
    AllowOrigins: []string{"*"},  // ⚠️ Too permissive for production
    AllowMethods: []string{"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"},
    AllowHeaders: []string{"Origin", "Accept", "Content-Type", "Authorization"},
})

// Security headers
helmet.Default()  // Sets: X-Frame-Options, X-Content-Type-Options, etc.
```

**Improvements Needed:**
- Whitelist specific origins (not "*")
- Add rate limiting headers
- Implement CSRF protection

### 7.5 Critical Security Gaps

**High Priority Fixes:**
1. ❌ **No authentication on report endpoints**
   - Risk: Data breach, unauthorized access
   - Fix: Add `auth.Authentication()` middleware

2. ❌ **No authorization (RBAC)**
   - Risk: Students can access other students' data
   - Fix: Implement role-based middleware

3. ❌ **WebSocket has no authentication**
   - Risk: Anyone can connect and send events
   - Fix: Verify JWT on initial WS connection

4. ❌ **Secrets in .env file**
   - Risk: Exposed if committed to Git
   - Fix: Use secrets management (Vault, AWS Secrets Manager)

5. ❌ **No input validation**
   - Risk: Malformed data, application crashes
   - Fix: Use validator library, sanitize inputs

---

## 8. Scalability & Performance

### 8.1 Scale Requirements

**Target Load:**
- 1,000 schools
- 30,000 classrooms
- 900,000 students
- 3.3 billion events/year (10 events/student/day)

**Performance SLAs:**
- API Response Time: <100ms (p95)
- Report Generation: <2s (p95)
- WebSocket Latency: <50ms
- Database Query: <500ms (p95)
- Event Processing: <1s from publish to storage

### 8.2 Current Scalability Analysis

**Bottlenecks:**

1. **In-Memory Session Storage**
   - Limit: Single server RAM (~10GB = 1M sessions)
   - Issue: Cannot scale horizontally
   - Fix: Redis with session replication

2. **In-Memory Event Queue**
   - Limit: 5,000 events buffer
   - Issue: Lost on crash, blocks on overflow
   - Fix: Persistent queue (RabbitMQ, Kafka)

3. **WebSocket Connections**
   - Limit: ~10,000 concurrent connections per server
   - Issue: Connections tied to single server
   - Fix: Load balancer with sticky sessions, or Redis pub/sub

4. **Database Queries**
   - Issue: No caching, direct DB queries
   - Fix: Redis cache for reports (5-min TTL)

5. **Events Table Growth**
   - Issue: Will reach billions of records
   - Fix: Table partitioning by month

### 8.3 Optimization Strategies

#### 8.3.1 Database Optimizations

**1. Table Partitioning (Events, Responses)**
```sql
-- Partition events by month
CREATE TABLE events_2025_10 PARTITION OF events
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
```

**2. Materialized Views (Reports)**
```sql
CREATE MATERIALIZED VIEW mv_student_performance AS
SELECT 
    student_id,
    COUNT(*) as attempts,
    SUM(CASE WHEN correct THEN 1 ELSE 0 END) as correct,
    DATE_TRUNC('day', submitted_at) as day
FROM responses
GROUP BY student_id, DATE_TRUNC('day', submitted_at);

REFRESH MATERIALIZED VIEW mv_student_performance;
```

**3. Connection Pooling**
```go
db.DB().SetMaxOpenConns(50)
db.DB().SetMaxIdleConns(10)
db.DB().SetConnMaxLifetime(5 * time.Minute)
```

**4. Query Optimization**
- Add missing indexes (see Section 4.4)
- Use EXPLAIN ANALYZE for slow queries
- Denormalize read-heavy tables

#### 8.3.2 Caching Strategy

**Redis Cache Layers:**

**L1: Session Cache**
- Key: `session:{sessionID}`
- TTL: 24 hours
- Reduces DB queries for auth

**L2: Report Cache**
- Key: `report:student:{id}:perf`
- TTL: 5 minutes
- Cache expensive aggregations

**L3: User Cache**
- Key: `user:{email}`
- TTL: 1 hour
- Reduce user lookups

**Cache Invalidation:**
- On logout: Delete session
- On new response: Invalidate student report cache
- On user update: Invalidate user cache

#### 8.3.3 Load Balancing

**Horizontal Scaling:**
```
                  ┌─────────────┐
                  │Load Balancer│
                  └──────┬──────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
   │ API Srv │      │ API Srv │      │ API Srv │
   │   #1    │      │   #2    │      │   #3    │
   └────┬────┘      └────┬────┘      └────┬────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
              ┌──────────▼──────────┐
              │  PostgreSQL (Primary)│
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │  Read Replicas (2+) │
              └─────────────────────┘
```

**Requirements:**
- Sticky sessions for WebSocket (or Redis pub/sub)
- Shared Redis for sessions
- Read replicas for reports

### 8.4 Performance Monitoring

**Metrics to Track:**
- Request rate (req/sec)
- Response time (p50, p95, p99)
- Error rate (4xx, 5xx)
- Database query time
- Event queue depth
- Worker pool saturation
- WebSocket connection count

**Tools:**
- Prometheus (metrics collection)
- Grafana (dashboards)
- Jaeger (distributed tracing)
- pgBadger (PostgreSQL log analysis)

---

## 9. Technology Stack

### 9.1 Technology Choices & Justification

| Component | Technology | Reason |
|-----------|------------|--------|
| **Language** | Go 1.19 | - High performance<br>- Excellent concurrency (goroutines)<br>- Strong typing<br>- Fast compilation |
| **Web Framework** | Gin | - High performance (40x faster than Martini)<br>- Minimal boilerplate<br>- Good middleware support<br>- Active community |
| **Database** | PostgreSQL 14 | - Mature, battle-tested<br>- JSONB for flexible schemas<br>- Strong consistency (ACID)<br>- Advanced indexing (GIN, BRIN)<br>- Partitioning support |
| **ORM** | GORM | - Most popular Go ORM<br>- Auto-migration<br>- Hooks and callbacks<br>- Preloading (N+1 prevention) |
| **Authentication** | JWT | - Stateless (scalable)<br>- Cross-platform<br>- Industry standard<br>- Self-contained (claims in token) |
| **WebSocket** | Gorilla WebSocket | - Production-ready<br>- RFC 6455 compliant<br>- Low overhead<br>- Active maintenance |
| **Containerization** | Docker | - Consistent environments<br>- Easy deployment<br>- Isolation<br>- Microservices ready |

### 9.2 Dependencies

See `go.mod` for complete list. Key dependencies:

```go
require (
    github.com/gin-gonic/gin v1.9.1          // Web framework
    github.com/jinzhu/gorm v1.9.16           // ORM
    github.com/lib/pq v1.10.9                // PostgreSQL driver
    github.com/golang-jwt/jwt v3.2.2+incompatible  // JWT
    github.com/gorilla/websocket v1.5.0      // WebSocket
    golang.org/x/crypto v0.14.0              // Password hashing
    github.com/danielkov/gin-helmet v0.0.0  // Security headers
)
```

### 9.3 Alternative Technologies Considered

**Language:**
- ❌ Python (Flask/Django): Slower, GIL limits concurrency
- ❌ Node.js (Express): Single-threaded, callback hell
- ❌ Java (Spring): Verbose, slower startup
- ✅ **Go**: Best balance of performance, simplicity, concurrency

**Database:**
- ❌ MongoDB: No ACID, eventual consistency issues
- ❌ MySQL: Weaker JSON support, partitioning limitations
- ✅ **PostgreSQL**: Best for structured + semi-structured (JSONB) data

**Message Queue:**
- ❌ In-memory channel: Not durable (current implementation)
- ✅ RabbitMQ: Durable, mature, good for medium scale
- ✅ Kafka: High throughput, but complex (overkill for now)

---

## 10. Deployment Strategy

### 10.1 Current Deployment (Docker Compose)

**Services:**
1. **app** - Go application
2. **postgres** - PostgreSQL database

**Configuration:**
```yaml
version: '3'
services:
  app:
    build: .
    ports: ["9090:9090"]
    depends_on: [postgres]
    
  postgres:
    image: postgres
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: eduanalytics
    ports: ["5432:5432"]
    volumes: [postgres:/var/lib/postgresql/data]
```

**Limitations:**
- No health checks
- No resource limits
- Single instance (no HA)
- Manual migrations

### 10.2 Production Deployment Architecture

**Recommended: Kubernetes (k8s)**

```yaml
# Deployment structure
eduanalytics/
├── api-deployment.yaml        # 3 replicas, auto-scaling
├── postgres-statefulset.yaml  # Primary + 2 replicas
├── redis-deployment.yaml      # Session store
├── nginx-ingress.yaml         # Load balancer
├── configmap.yaml             # Non-secret config
└── secret.yaml                # Sensitive data
```

**Key Features:**
- Auto-scaling (HPA based on CPU/memory)
- Self-healing (pod restarts)
- Rolling updates (zero-downtime)
- Health checks (liveness/readiness probes)
- Secret management
- Service discovery

### 10.3 CI/CD Pipeline

**Recommended: GitHub Actions**

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: go test ./...
      
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Build Docker image
        run: docker build -t eduanalytics:${{ github.sha }} .
      - name: Push to registry
        run: docker push eduanalytics:${{ github.sha }}
  
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to k8s
        run: kubectl set image deployment/api api=eduanalytics:${{ github.sha }}
```

### 10.4 Database Migration Strategy

**Current: Manual goose**
```bash
goose postgres "connection-string" up
```

**Production: Automated in CI/CD**
```yaml
# Kubernetes Job for migrations
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migration
spec:
  template:
    spec:
      containers:
      - name: goose
        image: eduanalytics:latest
        command: ["goose", "postgres", "$(DB_URL)", "up"]
      restartPolicy: Never
```

### 10.5 Monitoring & Logging

**Metrics: Prometheus + Grafana**
- API request rate, latency, errors
- Database connection pool usage
- Event queue depth
- Worker pool saturation

**Logging: ELK Stack (Elasticsearch, Logstash, Kibana)**
- Structured JSON logs
- Correlation ID tracking
- Error aggregation

**Alerting: AlertManager**
- High error rate (>1%)
- Slow response time (p95 >500ms)
- Database connection exhaustion
- Event queue near capacity

---

## 11. Monitoring & Observability

### 11.1 Logging Strategy

**Current Implementation:**
- Structured logging with correlation IDs
- File-based logs (`/tmp/eduanalytics.log`)
- Log rotation (10MB, 5 backups, 30 days)

**Log Levels:**
- ERROR: Failures, exceptions
- WARN: Degraded performance, anomalies
- INFO: Important business events (quiz created, user login)
- DEBUG: Detailed diagnostic info (dev only)

**Log Format:**
```json
{
  "level": "info",
  "timestamp": "2025-10-07T14:32:10Z",
  "correlation_id": "a1b2c3d4-e5f6-7890",
  "user_id": 101,
  "message": "Quiz created successfully",
  "metadata": {"quiz_id": 15, "classroom_id": 10}
}
```

### 11.2 Metrics Collection (Not Implemented)

**Recommended: Prometheus Metrics**

```go
// Example metrics
var (
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request duration",
        },
        []string{"method", "endpoint", "status"},
    )
    
    eventQueueDepth = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "event_queue_depth",
            Help: "Current event queue size",
        },
    )
)
```

**Key Metrics:**
- `http_request_duration_seconds` - Request latency
- `http_requests_total` - Request count by endpoint
- `event_queue_depth` - Event queue size
- `db_connections_active` - Active DB connections
- `websocket_connections_active` - Active WS connections

### 11.3 Distributed Tracing (Not Implemented)

**Recommended: Jaeger**

**Trace Flow:**
```
API Request (Trace ID: abc123)
├── Controller (Span 1)
│   ├── Repository (Span 2)
│   │   └── Database Query (Span 3)
│   └── Event Publish (Span 4)
│       └── Worker Process (Span 5)
│           └── Database Insert (Span 6)
```

**Benefits:**
- Visualize request flow
- Identify slow components
- Debug distributed systems

### 11.4 Health Checks

**Endpoint (Not Implemented):**
```go
GET /health

Response:
{
  "status": "healthy",
  "version": "1.0.0",
  "checks": {
    "database": "ok",
    "redis": "ok",
    "disk_space": "ok"
  },
  "uptime_seconds": 3600
}
```

### 11.5 Alerting Rules

**Critical Alerts (Page on-call):**
- API error rate >1% for 5 minutes
- Database connection pool exhausted
- Event queue >4000 (80% capacity)
- Disk usage >90%

**Warning Alerts (Slack notification):**
- API latency p95 >500ms for 10 minutes
- Database query time p95 >1s
- Event processing lag >1 minute

---

## 12. Assumptions & Constraints

### 12.1 Assumptions Made

**Scale Assumptions:**
1. 1,000 schools (static, not rapidly growing)
2. 30 classrooms per school (average)
3. 30 students per classroom (average)
4. 10 events per student per day (conservative)
5. Quizzes are short-lived (<1 hour)
6. Read:Write ratio = 80:20 (read-heavy)

**Functional Assumptions:**
1. Quiz questions are multiple-choice (single correct answer)
2. Whiteboard app is web-based (no mobile-specific features)
3. Notebook app supports both web and mobile
4. Real-time sync only needed during active quiz
5. Reports can tolerate 5-minute staleness (caching acceptable)
6. Event processing can be asynchronous (eventual consistency)

**Technical Assumptions:**
1. PostgreSQL can handle 996GB/year growth (true with partitioning)
2. Go's concurrency is sufficient (no need for distributed workers initially)
3. In-memory event queue is acceptable for MVP (not production)
4. JWT expiry times are acceptable (5 min access, 10 min refresh)

### 12.2 Constraints

**Business Constraints:**
1. MVP delivery timeline (prioritize core features)
2. No budget for third-party services (use open-source)
3. Must support both Whiteboard and Notebook apps

**Technical Constraints:**
1. Go 1.19 (legacy version, should upgrade to 1.21+)
2. PostgreSQL 14+ (no MySQL/MongoDB option)
3. Docker-based deployment (no serverless)
4. REST + WebSocket (no GraphQL)

**Scalability Constraints:**
1. Single database instance (no sharding initially)
2. In-memory session storage (not distributed)
3. Single server WebSocket (no clustering)
4. Events table will hit size limits (need archival)

---

## 13. Alternative Approaches Considered

### 13.1 Event Storage

**Option A: Dedicated Event Store (Not Chosen)**
- Use: EventStoreDB, Apache Kafka
- Pros: Purpose-built, event sourcing, replay capability
- Cons: Additional complexity, learning curve, operational overhead

**Option B: PostgreSQL (Chosen)**
- Pros: Existing infrastructure, JSONB flexibility, SQL queries
- Cons: Not optimized for event streaming, partitioning required at scale

**Option C: Time-Series DB (Rejected)**
- Use: InfluxDB, TimescaleDB
- Pros: Optimized for time-series, automatic downsampling
- Cons: Less flexible for relational queries, additional service

**Decision:** PostgreSQL with partitioning is sufficient for current scale.

### 13.2 Real-Time Sync

**Option A: Polling (Rejected)**
- Students poll `/quiz/status` every 2 seconds
- Pros: Simple, RESTful
- Cons: High latency, wasteful (90% empty responses)

**Option B: Server-Sent Events / SSE (Rejected)**
- Server pushes updates to clients
- Pros: HTTP-based, built-in reconnection
- Cons: Unidirectional (server → client only)

**Option C: WebSocket (Chosen)**
- Bidirectional, persistent connection
- Pros: Low latency, bi-directional, real-time
- Cons: Stateful (scaling complexity)

**Decision:** WebSocket for best user experience, with future consideration for Redis pub/sub for scaling.

### 13.3 Session Management

**Option A: JWT-Only (Rejected)**
- No server-side session storage
- Pros: Stateless, horizontally scalable
- Cons: Cannot revoke tokens, logout doesn't work

**Option B: Database Sessions (Rejected)**
- Store sessions in PostgreSQL
- Pros: Persistent, durable
- Cons: DB query on every request (slow)

**Option C: In-Memory + Redis (Chosen Path)**
- Current: In-memory (MVP)
- Future: Redis (production)
- Pros: Fast, persistent (Redis), scalable
- Cons: Additional service

**Decision:** In-memory for MVP, migrate to Redis before production.

### 13.4 Report Generation

**Option A: Real-Time Aggregation (Chosen)**
- Query database on-demand
- Pros: Always up-to-date, no staleness
- Cons: Slow for large datasets

**Option B: Materialized Views (Future Enhancement)**
- Pre-aggregate data, refresh hourly
- Pros: Fast queries, reduced DB load
- Cons: Stale data, refresh overhead

**Option C: OLAP Cube (Bonus - Not Implemented)**
- Use Cube.dev for measures/dimensions
- Pros: Ad-hoc queries, drill-down, flexible
- Cons: Additional complexity, learning curve

**Decision:** Start with real-time, add materialized views for popular reports, consider OLAP for advanced analytics.

### 13.5 Authentication

**Option A: Session Cookies (Rejected)**
- Traditional cookie-based sessions
- Pros: Simple, browser automatic handling
- Cons: CSRF issues, not ideal for mobile

**Option B: OAuth 2.0 (Rejected for MVP)**
- Delegate to Google, Microsoft
- Pros: No password management, SSO
- Cons: Requires external accounts, complex setup

**Option C: JWT (Chosen)**
- Self-contained tokens with refresh mechanism
- Pros: Stateless, mobile-friendly, scalable
- Cons: Cannot revoke (mitigated with session management)

**Decision:** JWT with session management for balance of scalability and control.

---

## 14. Future Enhancements

### 14.1 Short-Term (Next 3 Months)

**1. Critical Security Fixes**
- [ ] Add authentication to all endpoints
- [ ] Implement RBAC authorization
- [ ] Add input validation
- [ ] Migrate sessions to Redis
- [ ] Add WebSocket authentication

**2. Performance & Scalability**
- [ ] Implement table partitioning (events, responses)
- [ ] Add database read replicas
- [ ] Implement report caching (Redis)
- [ ] Add missing database indexes
- [ ] Implement connection pooling

**3. Operational Improvements**
- [ ] Add health check endpoint
- [ ] Implement graceful shutdown
- [ ] Setup monitoring (Prometheus + Grafana)
- [ ] Add distributed tracing (Jaeger)
- [ ] Setup alerting (AlertManager)

### 14.2 Medium-Term (3-6 Months)

**4. Feature Enhancements**
- [ ] Pagination on all reports
- [ ] Date range filtering
- [ ] Export reports (CSV, PDF)
- [ ] Bulk import endpoints
- [ ] Materialized views for reports
- [ ] Email report scheduling

**5. Advanced Analytics**
- [ ] Trend analysis (performance over time)
- [ ] Comparative reports (student vs class average)
- [ ] Predictive analytics (at-risk students)
- [ ] Content recommendation engine
- [ ] Learning curve analysis

**6. Developer Experience**
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Client SDKs (JavaScript, Python)
- [ ] Postman collections
- [ ] Integration tests
- [ ] Load tests

### 14.3 Long-Term (6-12 Months)

**7. Generic Query Framework (Bonus)**
- [ ] Integrate Cube.dev for OLAP queries
- [ ] Dimension support (student, classroom, school, date, subject)
- [ ] Measure support (count, avg, sum, min, max)
- [ ] Ad-hoc query builder UI
- [ ] Saved queries and dashboards

**8. Platform Evolution**
- [ ] GraphQL API (alternative to REST)
- [ ] Multi-language support (i18n)
- [ ] Mobile SDKs (iOS, Android)
- [ ] Plugin architecture (custom reports)
- [ ] White-label support (per-school branding)

**9. Machine Learning**
- [ ] Difficulty prediction (question analysis)
- [ ] Dropout risk prediction
- [ ] Personalized learning paths
- [ ] Automated content tagging
- [ ] Anomaly detection (cheating, unusual patterns)

### 14.4 Technical Debt to Address

**High Priority:**
1. Replace in-memory event queue with RabbitMQ/Kafka
2. Replace in-memory sessions with Redis
3. Fix WebSocket scaling (use Redis pub/sub)
4. Implement data archival strategy
5. Add comprehensive test suite

**Medium Priority:**
6. Upgrade Go version (1.19 → 1.21+)
7. Migrate to GORM v2 (v1 is legacy)
8. Refactor error handling (consistent patterns)
9. Add request rate limiting
10. Implement circuit breakers

**Low Priority:**
11. Refactor to microservices (if scale demands)
12. Consider gRPC for internal services
13. Evaluate ClickHouse for analytics workload
14. Consider CockroachDB for geo-distribution

---

## Appendix A: Glossary

**ACID** - Atomicity, Consistency, Isolation, Durability (database properties)  
**API** - Application Programming Interface  
**CORS** - Cross-Origin Resource Sharing  
**ER** - Entity-Relationship  
**GIN** - Generalized Inverted Index (PostgreSQL index type)  
**GORM** - Go Object-Relational Mapping library  
**HPA** - Horizontal Pod Autoscaler (Kubernetes)  
**JWT** - JSON Web Token  
**OLAP** - Online Analytical Processing  
**ORM** - Object-Relational Mapping  
**RBAC** - Role-Based Access Control  
**REST** - Representational State Transfer  
**SSE** - Server-Sent Events  
**TTL** - Time To Live  
**WebSocket** - Bidirectional communication protocol

## Appendix B: References

**Documentation:**
- [Go Documentation](https://go.dev/doc/)
- [Gin Framework](https://gin-gonic.com/docs/)
- [GORM](https://gorm.io/docs/)
- [PostgreSQL](https://www.postgresql.org/docs/)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [WebSocket RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455)

**Design Patterns:**
- [Go Design Patterns](https://refactoring.guru/design-patterns/go)
- [Repository Pattern](https://martinfowler.com/eaaCatalog/repository.html)
- [Event Sourcing](https://martinfowler.com/eaaDev/EventSourcing.html)

**Best Practices:**
- [Twelve-Factor App](https://12factor.net/)
- [RESTful API Design](https://restfulapi.net/)
- [PostgreSQL Performance](https://wiki.postgresql.org/wiki/Performance_Optimization)

---

**Document Status:** Draft v1.0  
**Last Updated:** October 7, 2025  
**Next Review:** When implementing Phase 2 features

**Feedback:** For questions or suggestions, contact shubham@orgosys.com


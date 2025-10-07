# Sequence Diagrams - EduAnalytics Reporting Framework

## Table of Contents
1. [Quiz Creation Flow](#1-quiz-creation-flow)
2. [Real-time Quiz Session (WebSocket)](#2-real-time-quiz-session-websocket)
3. [Student Response Submission](#3-student-response-submission)
4. [Report Generation Flow](#4-report-generation-flow)
5. [Event Processing Pipeline](#5-event-processing-pipeline)
6. [User Authentication Flow](#6-user-authentication-flow)

---

## 1. Quiz Creation Flow

**Description:** Teacher creates a quiz from the Whiteboard app, which is stored in the database and tracked as an event.

```mermaid
sequenceDiagram
    actor Teacher
    participant Whiteboard as Whiteboard App
    participant API as API Server
    participant Auth as Auth Middleware
    participant QuizCtrl as Quiz Controller
    participant EventCtrl as Events Controller
    participant EventQueue as Event Queue
    participant QuizRepo as Quiz Repository
    participant EventWorker as Event Worker
    participant DB as PostgreSQL

    Teacher->>Whiteboard: Create Quiz<br/>(title, classroom, questions)
    Whiteboard->>API: POST /api/v1/quizzes<br/>Authorization: Bearer {token}
    
    API->>Auth: Verify JWT Token
    Auth->>DB: Validate Session
    DB-->>Auth: Session Valid
    Auth-->>API: User Authenticated
    
    API->>QuizCtrl: CreateQuiz(quiz)
    QuizCtrl->>QuizRepo: CreateQuiz(quiz)
    QuizRepo->>DB: INSERT INTO quizzes
    DB-->>QuizRepo: Quiz ID: 15
    QuizRepo-->>QuizCtrl: Quiz Created
    
    QuizCtrl->>EventCtrl: PublishEvent("quiz_created")
    EventCtrl->>EventQueue: Push Event to Queue
    EventQueue-->>EventCtrl: Queued
    
    QuizCtrl-->>API: Success (quiz_id: 15)
    API-->>Whiteboard: 200 OK {quiz}
    Whiteboard-->>Teacher: Quiz Created Successfully
    
    Note over EventQueue,EventWorker: Asynchronous Processing
    EventQueue->>EventWorker: Consume Event
    EventWorker->>DB: INSERT INTO events<br/>(event_name='quiz_created',<br/>app='whiteboard', ...)
    DB-->>EventWorker: Event Logged
```

**Key Points:**
- Synchronous: Quiz creation (fast response to user)
- Asynchronous: Event logging (doesn't block user)
- Authentication required before any operation
- Event queue decouples business logic from analytics

---

## 2. Real-time Quiz Session (WebSocket)

**Description:** Teacher starts a quiz and displays questions in real-time. Students connect via WebSocket and receive updates.

```mermaid
sequenceDiagram
    actor Teacher
    actor Student1
    actor Student2
    participant Whiteboard as Whiteboard App
    participant Notebook1 as Notebook App (S1)
    participant Notebook2 as Notebook App (S2)
    participant WSServer as WebSocket Server
    participant EventCtrl as Events Controller
    participant EventQueue as Event Queue
    participant DB as PostgreSQL

    Note over Teacher,Student2: Initial Connection Phase
    
    Teacher->>Whiteboard: Open Quiz Session
    Whiteboard->>WSServer: WS Connect<br/>{user_id: 5, classroom_id: 10}
    WSServer-->>Whiteboard: Connected
    
    Student1->>Notebook1: Join Quiz
    Notebook1->>WSServer: WS Connect<br/>{user_id: 101, classroom_id: 10}
    WSServer->>WSServer: Add to classroom_10 group
    WSServer-->>Notebook1: Connected
    
    Student2->>Notebook2: Join Quiz
    Notebook2->>WSServer: WS Connect<br/>{user_id: 102, classroom_id: 10}
    WSServer->>WSServer: Add to classroom_10 group
    WSServer-->>Notebook2: Connected
    
    Note over Teacher,DB: Quiz Start Phase
    
    Teacher->>Whiteboard: Start Quiz
    Whiteboard->>WSServer: {event: "quiz_started",<br/>quiz_id: 15}
    
    WSServer->>EventCtrl: PublishEvent("quiz_started")
    EventCtrl->>EventQueue: Queue Event
    
    WSServer->>Notebook1: Broadcast: quiz_started
    WSServer->>Notebook2: Broadcast: quiz_started
    Notebook1-->>Student1: Quiz Started!
    Notebook2-->>Student2: Quiz Started!
    
    Note over Teacher,DB: Question Display Phase
    
    Teacher->>Whiteboard: Display Question 1
    Whiteboard->>WSServer: {event: "question_displayed",<br/>question_id: 45}
    
    WSServer->>EventCtrl: PublishEvent("question_displayed")
    EventCtrl->>EventQueue: Queue Event
    
    WSServer->>Notebook1: Broadcast: question_displayed
    WSServer->>Notebook2: Broadcast: question_displayed
    Notebook1-->>Student1: Show Question 1
    Notebook2-->>Student2: Show Question 1
    
    Note over Student1,DB: Student Response Phase
    
    Student1->>Notebook1: Submit Answer "B"
    Notebook1->>WSServer: {event: "answer_submitted",<br/>answer: "B", time_spent: 45.5}
    
    WSServer->>DB: INSERT INTO responses
    DB-->>WSServer: Response Saved
    
    WSServer->>EventCtrl: PublishEvent("answer_submitted")
    EventCtrl->>EventQueue: Queue Event
    
    WSServer->>Whiteboard: Broadcast: answer_received<br/>(student: 101)
    Whiteboard-->>Teacher: Student 1 Answered
    
    Note over Teacher,DB: Quiz End Phase
    
    Teacher->>Whiteboard: End Quiz
    Whiteboard->>WSServer: {event: "quiz_ended"}
    
    WSServer->>EventCtrl: PublishEvent("quiz_ended")
    EventCtrl->>EventQueue: Queue Event
    
    WSServer->>Notebook1: Broadcast: quiz_ended
    WSServer->>Notebook2: Broadcast: quiz_ended
    Notebook1-->>Student1: Quiz Completed!
    Notebook2-->>Student2: Quiz Completed!
    
    WSServer->>WSServer: Cleanup connections
```

**Key Points:**
- Persistent WebSocket connections for low-latency
- Classroom-based broadcasting (all students in classroom receive updates)
- Teacher controls flow (starts quiz, displays questions, ends quiz)
- Students can submit answers independently
- All events logged asynchronously for analytics
- Responses saved synchronously (important for real-time feedback)

---

## 3. Student Response Submission

**Description:** Alternative flow for students submitting answers via REST API (non-WebSocket).

```mermaid
sequenceDiagram
    actor Student
    participant Notebook as Notebook App
    participant API as API Server
    participant RespCtrl as Response Controller
    participant EventCtrl as Events Controller
    participant EventQueue as Event Queue
    participant RespRepo as Response Repository
    participant EventWorker as Event Worker
    participant DB as PostgreSQL

    Student->>Notebook: Select Answer "C"<br/>for Question ID: 45
    Notebook->>Notebook: Calculate time_spent: 38.2s
    Notebook->>Notebook: Validate answer against<br/>correct_option
    
    Notebook->>API: POST /api/v1/responses<br/>{<br/>  student_id: 101,<br/>  question_id: 45,<br/>  answer: "C",<br/>  correct: true,<br/>  time_spent: 38.2<br/>}
    
    API->>RespCtrl: SubmitResponse(response)
    
    RespCtrl->>RespRepo: CreateResponse(response)
    RespRepo->>DB: BEGIN TRANSACTION
    RespRepo->>DB: INSERT INTO responses<br/>(student_id, question_id,<br/>answer, correct, time_spent)
    DB-->>RespRepo: Response ID: 12345
    RespRepo->>DB: COMMIT
    RespRepo-->>RespCtrl: Response Saved
    
    RespCtrl->>EventCtrl: PublishEvent({<br/>  event_name: "question_submitted",<br/>  app: "notebook",<br/>  user_id: 101,<br/>  metadata: {<br/>    question_id: 45,<br/>    answer: "C",<br/>    correct: true,<br/>    time_spent: 38.2<br/>  }<br/>})
    
    EventCtrl->>EventQueue: Push to Queue<br/>(capacity: 5000)
    EventQueue-->>EventCtrl: Queued
    
    RespCtrl-->>API: Success
    API-->>Notebook: 200 OK<br/>{success: true, message: "Response recorded"}
    Notebook-->>Student: Answer Submitted ✓
    
    Note over EventQueue,DB: Asynchronous Event Processing
    
    EventQueue->>EventWorker: Worker Pool Consumes
    EventWorker->>EventWorker: Marshal metadata to JSON
    EventWorker->>DB: INSERT INTO events<br/>(event_name, app, user_id,<br/>metadata, timestamp)
    DB-->>EventWorker: Event ID: 98765
    EventWorker-->>EventQueue: Acknowledge
```

**Key Points:**
- REST API as alternative to WebSocket
- Answer validation happens client-side (app knows correct answer)
- Response saved synchronously (critical for consistency)
- Event logged asynchronously (for analytics, not critical path)
- Transaction ensures data integrity
- Event worker pool processes events in background

---

## 4. Report Generation Flow

**Description:** Teacher or admin requests a student performance report.

```mermaid
sequenceDiagram
    actor User as Teacher/Admin
    participant App as Web/Mobile App
    participant API as API Server
    participant Auth as Auth Middleware
    participant ReportCtrl as Report Controller
    participant ReportRepo as Reports Repository
    participant DB as PostgreSQL
    participant Cache as Redis Cache (Future)

    User->>App: Request Student Report<br/>(student_id: 101)
    App->>API: GET /api/v1/student-performance?student_id=101<br/>Authorization: Bearer {token}
    
    API->>Auth: Verify JWT
    Auth->>Auth: Validate Token Signature
    Auth->>Auth: Check Session Validity
    Auth-->>API: Authenticated as Teacher
    
    Note over API,Auth: Authorization Check (Missing in Current Implementation!)
    API->>API: ⚠️ Should Check:<br/>Is this teacher allowed to<br/>view this student's data?
    
    API->>ReportCtrl: StudentPerformanceReport(student_id: 101)
    
    opt Future Enhancement: Check Cache
        ReportCtrl->>Cache: GET report:student:101
        Cache-->>ReportCtrl: Cache Miss
    end
    
    ReportCtrl->>ReportRepo: GetStudentPerformanceReport(ctx, 101)
    
    ReportRepo->>DB: Execute Analytics Query:<br/>SELECT u.name,<br/>  COUNT(r.id) as attempts,<br/>  SUM(CASE WHEN r.correct THEN 1 ELSE 0 END) as correct,<br/>  ROUND(...) as accuracy<br/>FROM responses r<br/>JOIN users u ON u.id = r.student_id<br/>WHERE r.student_id = 101<br/>GROUP BY u.name
    
    DB-->>ReportRepo: Result:<br/>name: "Alice",<br/>attempts: 245,<br/>correct: 198,<br/>accuracy: 0.81
    
    ReportRepo-->>ReportCtrl: Return aggregated data
    
    opt Future Enhancement: Cache Result
        ReportCtrl->>Cache: SET report:student:101<br/>TTL: 300s
    end
    
    ReportCtrl->>ReportCtrl: Format Response:<br/>{<br/>  student: "Alice",<br/>  attempts: 245,<br/>  correct: 198,<br/>  accuracy: 0.81<br/>}
    
    ReportCtrl-->>API: Report Data
    API-->>App: 200 OK {success: true, data: {...}}
    App-->>User: Display Performance Report
    
    Note over User,App: Report shows:<br/>- Total attempts: 245<br/>- Correct answers: 198<br/>- Accuracy: 81%
```

**Key Points:**
- Authentication required (JWT)
- **Missing:** Authorization check (should verify teacher can access this student)
- Direct database query (no caching in current implementation)
- Single aggregation query for efficiency
- Future enhancement: Redis caching (5-minute TTL)
- Report is read-only (no data modification)

---

## 5. Event Processing Pipeline

**Description:** Detailed view of how events flow from generation to storage.

```mermaid
sequenceDiagram
    participant Source as Event Source<br/>(Controllers)
    participant EventCtrl as Events Controller
    participant Queue as Event Queue<br/>(Chan, cap: 5000)
    participant Worker1 as Worker Pool<br/>Worker #1
    participant Worker2 as Worker #2
    participant Worker3 as Worker #3
    participant EventRepo as Events Repository
    participant DB as PostgreSQL

    Note over Source,DB: Event Generation Phase
    
    Source->>EventCtrl: PublishEvent({<br/>  event_name: "quiz_started",<br/>  app: "whiteboard",<br/>  user_id: 5,<br/>  quiz_id: 15,<br/>  classroom_id: 10<br/>})
    
    EventCtrl->>Queue: EventQueue <- event
    
    alt Queue Not Full
        Queue-->>EventCtrl: Queued Successfully
        EventCtrl-->>Source: Non-blocking return
    else Queue Full (5000 events)
        Queue-->>EventCtrl: ⚠️ Blocks until space available
        Note over Queue: Current Implementation Issue:<br/>No overflow handling,<br/>will block caller
    end
    
    Note over Queue,DB: Event Processing Phase<br/>(Multiple Workers)
    
    Queue->>Worker1: Consume Event #1
    Queue->>Worker2: Consume Event #2
    Queue->>Worker3: Consume Event #3
    
    par Worker #1
        Worker1->>Worker1: Set timestamp = NOW()
        Worker1->>Worker1: Marshal metadata to JSON
        Worker1->>EventRepo: CreateEvent(event)
        EventRepo->>DB: BEGIN TRANSACTION
        EventRepo->>DB: INSERT INTO events<br/>(event_name, app, user_id, ...)
        DB-->>EventRepo: Event ID: 1001
        EventRepo->>DB: COMMIT
        EventRepo-->>Worker1: Success
    and Worker #2
        Worker2->>Worker2: Set timestamp = NOW()
        Worker2->>Worker2: Marshal metadata to JSON
        Worker2->>EventRepo: CreateEvent(event)
        EventRepo->>DB: BEGIN TRANSACTION
        EventRepo->>DB: INSERT INTO events<br/>(event_name, app, user_id, ...)
        DB-->>EventRepo: Event ID: 1002
        EventRepo->>DB: COMMIT
        EventRepo-->>Worker2: Success
    and Worker #3
        Worker3->>Worker3: Set timestamp = NOW()
        Worker3->>Worker3: Marshal metadata to JSON
        Worker3->>EventRepo: CreateEvent(event)
        EventRepo->>DB: BEGIN TRANSACTION
        EventRepo->>DB: INSERT INTO events<br/>(event_name, app, user_id, ...)
        DB-->>EventRepo: Event ID: 1003
        EventRepo->>DB: COMMIT
        EventRepo-->>Worker3: Success
    end
    
    alt Processing Failure
        Worker1->>Worker1: Error: DB connection lost
        Worker1->>Worker1: ⚠️ Log error and exit<br/>(Current Implementation)
        Note over Worker1: Issue: No retry mechanism<br/>Event is lost!
    end
    
    Note over Queue,DB: Workers continuously process<br/>until application shutdown
```

**Key Points:**
- **Asynchronous Processing:** Events don't block API responses
- **Worker Pool:** Configurable concurrency (default: set on startup)
- **Buffered Channel:** 5,000 event capacity
- **Current Issues:**
  - No persistent queue (events lost on crash)
  - No retry mechanism for failed events
  - No dead-letter queue
  - Workers exit on error instead of retrying
- **Recommended Improvements:**
  - Use RabbitMQ/Kafka for persistence
  - Implement exponential backoff retry
  - Add dead-letter queue for failed events
  - Add circuit breaker for DB failures

---

## 6. User Authentication Flow

**Description:** Complete authentication lifecycle from login to logout.

```mermaid
sequenceDiagram
    actor User
    participant App as Client App
    participant API as API Server
    participant AuthCtrl as Auth Controller
    participant JWTSvc as JWT Service
    participant SessionMgr as Session Manager
    participant UserRepo as User Repository
    participant DB as PostgreSQL

    Note over User,DB: 1. Login Flow
    
    User->>App: Enter email & password
    App->>API: POST /api/v1/auth/login<br/>{email, password}
    
    API->>AuthCtrl: Login(credentials)
    AuthCtrl->>UserRepo: GetUserByEmail(email)
    UserRepo->>DB: SELECT * FROM users<br/>WHERE email = ?
    DB-->>UserRepo: User record
    UserRepo-->>AuthCtrl: User{id, email, password_hash, role}
    
    AuthCtrl->>AuthCtrl: ValidatePassword(plain, hash)
    AuthCtrl->>AuthCtrl: ✓ Password matches
    
    AuthCtrl->>JWTSvc: CreateNewTokens(email, userAgent, IP)
    JWTSvc->>SessionMgr: CreateSession(email, userAgent, IP)
    
    SessionMgr->>SessionMgr: Generate SessionID (32-byte random)
    SessionMgr->>SessionMgr: Store in memory:<br/>sessions[sessionID] = Session{<br/>  email,<br/>  expires_at: now + 24h<br/>}
    SessionMgr-->>JWTSvc: Session{sessionID}
    
    JWTSvc->>JWTSvc: Create Access Token:<br/>Claims{<br/>  email,<br/>  session_id,<br/>  exp: now + 5min<br/>}<br/>Sign with ACCESS_SECRET
    
    JWTSvc->>JWTSvc: Create Refresh Token:<br/>Claims{<br/>  email,<br/>  session_id,<br/>  exp: now + 10min<br/>}<br/>Sign with REFRESH_SECRET
    
    JWTSvc-->>AuthCtrl: TokenDetails{<br/>  access_token,<br/>  refresh_token,<br/>  expires<br/>}
    
    AuthCtrl-->>API: Tokens
    API-->>App: 200 OK {access_token, refresh_token}
    App->>App: Store tokens securely
    App-->>User: Login Successful
    
    Note over User,DB: 2. Authenticated Request
    
    User->>App: Request Protected Resource
    App->>API: GET /api/v1/auth/.../<br/>Authorization: Bearer {access_token}
    
    API->>Auth: Authentication Middleware
    Auth->>JWTSvc: VerifyToken(token)
    JWTSvc->>JWTSvc: Parse & Validate Token
    JWTSvc->>JWTSvc: Verify Signature
    JWTSvc->>JWTSvc: Check Expiry
    
    JWTSvc->>SessionMgr: IsSessionValid(session_id)
    SessionMgr->>SessionMgr: Check session exists<br/>and not expired
    SessionMgr-->>JWTSvc: ✓ Valid
    
    JWTSvc->>UserRepo: GetUserByEmail(email)
    UserRepo->>DB: SELECT * FROM users
    DB-->>UserRepo: User record
    UserRepo-->>JWTSvc: User
    
    JWTSvc-->>Auth: User, Valid=true
    Auth->>API: Set user in context
    API->>API: Process request...
    API-->>App: 200 OK {data}
    
    Note over User,DB: 3. Token Refresh
    
    App->>App: Access token expired
    App->>API: POST /api/v1/auth/refresh<br/>Authorization: Bearer {refresh_token}
    
    API->>AuthCtrl: RefreshToken(refresh_token)
    AuthCtrl->>JWTSvc: RefreshToken(token, userAgent, IP)
    
    JWTSvc->>JWTSvc: Parse refresh token
    JWTSvc->>JWTSvc: Verify signature (REFRESH_SECRET)
    JWTSvc->>JWTSvc: Extract session_id
    
    JWTSvc->>SessionMgr: IsSessionValid(session_id)
    SessionMgr-->>JWTSvc: ✓ Valid
    
    JWTSvc->>JWTSvc: CreateNewTokens(email)
    Note over JWTSvc: Creates new access<br/>and refresh tokens
    
    JWTSvc-->>AuthCtrl: New TokenDetails
    AuthCtrl-->>API: New tokens
    API-->>App: 200 OK {new_access_token, new_refresh_token}
    App->>App: Update stored tokens
    
    Note over User,DB: 4. Logout
    
    User->>App: Click Logout
    App->>API: POST /api/v1/auth/logout<br/>Authorization: Bearer {access_token}
    
    API->>AuthCtrl: Logout()
    AuthCtrl->>AuthCtrl: Parse token to extract<br/>session_id
    
    AuthCtrl->>JWTSvc: InvalidateSession(session_id)
    JWTSvc->>SessionMgr: DeleteSession(session_id)
    
    SessionMgr->>SessionMgr: Remove from sessions map
    SessionMgr->>SessionMgr: Remove from user_sessions map
    SessionMgr-->>JWTSvc: Deleted
    
    JWTSvc-->>AuthCtrl: Success
    AuthCtrl-->>API: Success
    API-->>App: 200 OK
    App->>App: Clear stored tokens
    App-->>User: Logged Out
    
    Note over SessionMgr: Background Task:<br/>Every 15 minutes, cleanup<br/>expired sessions
```

**Key Points:**
- **Dual-Token System:**
  - Access Token: Short-lived (5 min), used for API requests
  - Refresh Token: Longer-lived (10 min), used to get new access tokens
- **Session Management:**
  - In-memory storage (⚠️ not production-ready)
  - 24-hour session expiry
  - Session ID embedded in JWT claims
- **Security:**
  - Passwords hashed with bcrypt
  - JWT signed with HMAC-SHA256
  - Separate secrets for access and refresh tokens
  - Session validation on every request
- **Current Issues:**
  - Sessions lost on server restart
  - Cannot scale horizontally (in-memory)
  - Refresh token expiry (10 min) is too short
- **Recommended Improvements:**
  - Use Redis for session storage
  - Increase refresh token lifetime to 7-30 days
  - Add refresh token rotation
  - Implement token revocation list

---

## Summary of Flows

| Flow | Sync/Async | Critical Path | Auth Required | Key Tables |
|------|------------|---------------|---------------|------------|
| Quiz Creation | Sync + Async Event | Yes | ✅ | quizzes, events |
| WebSocket Quiz Session | Real-time | Yes | ⚠️ Missing | responses, events |
| Response Submission | Sync + Async Event | Yes | ⚠️ Missing | responses, events |
| Report Generation | Sync | No (read-only) | ⚠️ Missing | responses, users, classrooms |
| Event Processing | Async | No (analytics) | N/A | events |
| Authentication | Sync | Yes | Public endpoints | users, sessions (in-memory) |

---

## Viewing These Diagrams

**Option 1: Mermaid Live Editor**
1. Copy any diagram code block
2. Paste into https://mermaid.live/

**Option 2: VS Code**
1. Install "Markdown Preview Mermaid Support" extension
2. Open this file and preview (Ctrl+Shift+V)

**Option 3: GitHub**
- GitHub natively renders Mermaid diagrams in markdown

**Option 4: Export as PNG/SVG**
- Use mermaid.live to export as image
- Or use mermaid-cli: `mmdc -i diagram.mmd -o diagram.png`

---

**Last Updated:** October 7, 2025  
**Version:** 1.0  
**Diagrams:** 6 key workflows


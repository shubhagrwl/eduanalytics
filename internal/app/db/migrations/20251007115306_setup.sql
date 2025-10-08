-- +goose Up
-- +goose StatementBegin

-- Schools
CREATE TABLE schools (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    address TEXT
);

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(20) CHECK (role IN ('admin', 'teacher', 'student')),
    school_id INT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Classrooms
CREATE TABLE classrooms (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    school_id INT REFERENCES schools(id),
    teacher_id INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Student Classrooms (junction table for many-to-many relationship)
CREATE TABLE student_classrooms (
    id SERIAL PRIMARY KEY,
    student_id INT REFERENCES users(id) ON DELETE CASCADE,
    classroom_id INT REFERENCES classrooms(id) ON DELETE CASCADE,
    enrolled_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(student_id, classroom_id)
);

-- Quizzes
CREATE TABLE quizzes (
    id SERIAL PRIMARY KEY,
    title VARCHAR(150),
    classroom_id INT REFERENCES classrooms(id),
    created_by INT REFERENCES users(id),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Questions
CREATE TABLE questions (
    id SERIAL PRIMARY KEY,
    quiz_id INT REFERENCES quizzes(id),
    question_text TEXT NOT NULL,
    options JSONB NOT NULL,
    correct_option VARCHAR(10) NOT NULL
);

-- Responses
CREATE TABLE responses (
    id SERIAL PRIMARY KEY,
    student_id INT REFERENCES users(id),
    question_id INT REFERENCES questions(id),
    answer VARCHAR(10),
    correct BOOLEAN,
    time_spent FLOAT,
    submitted_at TIMESTAMP DEFAULT NOW()
);

-- Event tracking (for reporting)
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_name VARCHAR(100) NOT NULL,
    app VARCHAR(50),
    user_id INT REFERENCES users(id),
    quiz_id INT,
    classroom_id INT,
    metadata JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_user_role ON users(role);
CREATE INDEX idx_event_type ON events(event_name);
CREATE INDEX idx_responses_student ON responses(student_id);
CREATE INDEX idx_student_classrooms_student ON student_classrooms(student_id);
CREATE INDEX idx_student_classrooms_classroom ON student_classrooms(classroom_id);
CREATE INDEX idx_classrooms_teacher ON classrooms(teacher_id);
CREATE INDEX idx_classrooms_school ON classrooms(school_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd

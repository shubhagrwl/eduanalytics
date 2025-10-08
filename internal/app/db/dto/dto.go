package dto

import (
	"time"
)

const (
	USER_TABLE              = "users"
	SCHOOL_TABLE            = "schools"
	CLASSROOM_TABLE         = "classrooms"
	STUDENT_CLASSROOM_TABLE = "student_classrooms"
	QUIZ_TABLE              = "quizzes"
	EVENT_TABLE             = "events"
	RESPONSE_TABLE          = "responses"
)

type User struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	Role      string    `json:"role"`
	SchoolId  int       `json:"school_id"`
	CreatedAt time.Time `json:"created_at"`
}

type School struct {
	Id      int    `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type Classroom struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	SchoolId  int       `json:"school_id"`
	TeacherId int       `json:"teacher_id"`
	CreatedAt time.Time `json:"created_at"`
}

type StudentClassroom struct {
	Id          int       `json:"id"`
	StudentId   int       `json:"student_id"`
	ClassroomId int       `json:"classroom_id"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

type Quiz struct {
	Id          int       `json:"id"`
	Title       string    `json:"title"`
	ClassroomId int       `json:"classroom_id"`
	CreatedBy   int       `json:"created_by"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	CreatedAt   time.Time `json:"created_at"`
}

type Question struct {
	Id            int         `json:"id"`
	QuizId        int         `json:"quiz_id"`
	QuestionText  string      `json:"question_text"`
	Options       interface{} `json:"options"`
	CorrectOption string      `json:"correct_option"`
}

type Response struct {
	Id          int       `json:"id"`
	StudentId   int       `json:"student_id"`
	QuestionId  int       `json:"question_id"`
	Answer      string    `json:"answer"`
	Correct     bool      `json:"correct"`
	TimeSpent   float64   `json:"time_spent"`
	SubmittedAt time.Time `json:"submitted_at"`
}

type Event struct {
	Id          int         `json:"id"`
	EventName   string      `json:"event_name"`
	App         string      `json:"app"`
	UserId      int         `json:"user_id"`
	QuizId      int         `json:"quiz_id"`
	ClassroomId int         `json:"classroom_id"`
	Metadata    interface{} `json:"metadata"`
	Timestamp   time.Time   `json:"timestamp"`
}

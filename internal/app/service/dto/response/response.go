package response

import (
	"eduanalytics/internal/app/db/dto"
	"time"
)

type ClassroomResponse struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	SchoolId  int       `json:"school_id"`
	TeacherId int       `json:"teacher_id"`
	CreatedAt time.Time `json:"created_at"`
}

type ClassroomWithStudentsResponse struct {
	Id        int               `json:"id"`
	Name      string            `json:"name"`
	SchoolId  int               `json:"school_id"`
	TeacherId int               `json:"teacher_id"`
	CreatedAt time.Time         `json:"created_at"`
	Students  []StudentResponse `json:"students"`
}

type StudentResponse struct {
	Id         int       `json:"id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	EnrolledAt time.Time `json:"enrolled_at,omitempty"`
}

func ToClassroomResponse(classroom *dto.Classroom) ClassroomResponse {
	return ClassroomResponse{
		Id:        classroom.Id,
		Name:      classroom.Name,
		SchoolId:  classroom.SchoolId,
		TeacherId: classroom.TeacherId,
		CreatedAt: classroom.CreatedAt,
	}
}

func ToClassroomResponseList(classrooms []dto.Classroom) []ClassroomResponse {
	var responses []ClassroomResponse
	for _, classroom := range classrooms {
		responses = append(responses, ToClassroomResponse(&classroom))
	}
	return responses
}

func ToStudentResponse(user *dto.User) StudentResponse {
	return StudentResponse{
		Id:    user.Id,
		Name:  user.Name,
		Email: user.Email,
	}
}

func ToStudentResponseList(users []dto.User) []StudentResponse {
	var responses []StudentResponse
	for _, user := range users {
		responses = append(responses, ToStudentResponse(&user))
	}
	return responses
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type TokenDetails3 struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type TokenDetails2 struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

// ErrorResponseData -
type ErrorResponseData struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse -
type ErrorResponse struct {
	Success bool              `json:"success" default:"false"`
	Error   ErrorResponseData `json:"data"`
}

type Response struct {
	Success bool `json:"success"`
	Data    Data `json:"data"`
}

type ResponseV2 struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Request interface{} `json:"request,omitempty"`
	// List    interface{} `json:"list,omitempty"`
}
type Data struct {
	Message string `json:"message"`
}

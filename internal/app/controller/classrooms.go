package controller

import (
	"eduanalytics/internal/app/db/dto"
	"eduanalytics/internal/app/db/repository"
	"eduanalytics/internal/app/service/correlation"
	request "eduanalytics/internal/app/service/dto/request"
	response "eduanalytics/internal/app/service/dto/response"
	"eduanalytics/internal/app/service/logger"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type IClassroomController interface {
	CreateClassroom(c *gin.Context)
	GetClassroom(c *gin.Context)
	GetClassrooms(c *gin.Context)
	UpdateClassroom(c *gin.Context)
	DeleteClassroom(c *gin.Context)
	EnrollStudents(c *gin.Context)
	UnenrollStudent(c *gin.Context)
	GetStudentsByClassroom(c *gin.Context)
	GetClassroomsByTeacher(c *gin.Context)
	GetClassroomsByStudent(c *gin.Context)
}

type ClassroomController struct {
	ClassroomRepo repository.IClassroomsRepository
	UserRepo      repository.IUsersRepository
}

func NewClassroomController(classroomRepo repository.IClassroomsRepository, userRepo repository.IUsersRepository) IClassroomController {
	return &ClassroomController{
		ClassroomRepo: classroomRepo,
		UserRepo:      userRepo,
	}
}

// CreateClassroom creates a new classroom
func (ctrl *ClassroomController) CreateClassroom(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	var req request.CreateClassroomRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Errorf("Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// Verify teacher exists and has teacher role
	teacher, err := ctrl.UserRepo.GetUser(ctx, "id = "+strconv.Itoa(req.TeacherId))
	if err != nil {
		log.Errorf("Teacher not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Teacher not found",
		})
		return
	}

	if teacher.Role != "teacher" {
		log.Errorf("User is not a teacher: %v", teacher.Id)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "User is not a teacher",
		})
		return
	}

	classroom := &dto.Classroom{
		Name:      req.Name,
		SchoolId:  req.SchoolId,
		TeacherId: req.TeacherId,
	}

	if err := ctrl.ClassroomRepo.CreateClassroom(ctx, classroom); err != nil {
		log.Errorf("Failed to create classroom: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to create classroom",
		})
		return
	}

	c.JSON(http.StatusCreated, response.ResponseV2{
		Success: true,
		Message: "Classroom created successfully",
		Data:    response.ToClassroomResponse(classroom),
	})
}

// GetClassroom retrieves a classroom by ID
func (ctrl *ClassroomController) GetClassroom(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	classroom, err := ctrl.ClassroomRepo.GetClassroomByID(ctx, id)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Data:    response.ToClassroomResponse(classroom),
	})
}

// GetClassrooms retrieves all classrooms (can filter by teacher or school)
func (ctrl *ClassroomController) GetClassrooms(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	teacherId := c.Query("teacher_id")
	schoolId := c.Query("school_id")

	var classrooms []dto.Classroom
	var err error

	if teacherId != "" {
		tid, parseErr := strconv.Atoi(teacherId)
		if parseErr != nil {
			log.Errorf("Invalid teacher ID: %v", parseErr)
			c.JSON(http.StatusBadRequest, response.ResponseV2{
				Success: false,
				Message: "Invalid teacher ID",
			})
			return
		}
		classrooms, err = ctrl.ClassroomRepo.GetClassroomsByTeacher(ctx, tid)
		if err != nil {
			log.Errorf("Failed to retrieve classrooms: %v", err)
			c.JSON(http.StatusInternalServerError, response.ResponseV2{
				Success: false,
				Message: "Failed to retrieve classrooms",
			})
			return
		}
	} else if schoolId != "" {
		sid, parseErr := strconv.Atoi(schoolId)
		if parseErr != nil {
			log.Errorf("Invalid school ID: %v", parseErr)
			c.JSON(http.StatusBadRequest, response.ResponseV2{
				Success: false,
				Message: "Invalid school ID",
			})
			return
		}
		classrooms, err = ctrl.ClassroomRepo.GetClassroomsBySchool(ctx, sid)
		if err != nil {
			log.Errorf("Failed to retrieve classrooms: %v", err)
			c.JSON(http.StatusInternalServerError, response.ResponseV2{
				Success: false,
				Message: "Failed to retrieve classrooms",
			})
			return
		}
	} else {
		// Get all classrooms - this might need authorization checks
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Please provide teacher_id or school_id parameter",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Data:    response.ToClassroomResponseList(classrooms),
	})
}

// UpdateClassroom updates a classroom
func (ctrl *ClassroomController) UpdateClassroom(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	var req request.UpdateClassroomRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Errorf("Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// Check if classroom exists
	_, err = ctrl.ClassroomRepo.GetClassroomByID(ctx, id)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	// If teacher ID is being updated, verify the new teacher
	if req.TeacherId > 0 {
		teacher, err := ctrl.UserRepo.GetUser(ctx, "id = "+strconv.Itoa(req.TeacherId))
		if err != nil {
			log.Errorf("Teacher not found: %v", err)
			c.JSON(http.StatusNotFound, response.ResponseV2{
				Success: false,
				Message: "Teacher not found",
			})
			return
		}

		if teacher.Role != "teacher" {
			log.Errorf("User is not a teacher: %v", teacher.Id)
			c.JSON(http.StatusBadRequest, response.ResponseV2{
				Success: false,
				Message: "User is not a teacher",
			})
			return
		}
	}

	classroom := &dto.Classroom{
		Name:      req.Name,
		TeacherId: req.TeacherId,
	}

	if err := ctrl.ClassroomRepo.UpdateClassroom(ctx, id, classroom); err != nil {
		log.Errorf("Failed to update classroom: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to update classroom",
		})
		return
	}

	// Get updated classroom
	updatedClassroom, _ := ctrl.ClassroomRepo.GetClassroomByID(ctx, id)

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Message: "Classroom updated successfully",
		Data:    response.ToClassroomResponse(updatedClassroom),
	})
}

// DeleteClassroom deletes a classroom
func (ctrl *ClassroomController) DeleteClassroom(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	// Check if classroom exists
	_, err = ctrl.ClassroomRepo.GetClassroomByID(ctx, id)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	if err := ctrl.ClassroomRepo.DeleteClassroom(ctx, id); err != nil {
		log.Errorf("Failed to delete classroom: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to delete classroom",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Message: "Classroom deleted successfully",
	})
}

// EnrollStudents enrolls students in a classroom
func (ctrl *ClassroomController) EnrollStudents(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	classroomId, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	var req request.EnrollStudentsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Errorf("Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	// Check if classroom exists
	_, err = ctrl.ClassroomRepo.GetClassroomByID(ctx, classroomId)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	// Verify all students exist and have student role
	for _, studentId := range req.StudentIds {
		student, err := ctrl.UserRepo.GetUser(ctx, "id = "+strconv.Itoa(studentId))
		if err != nil {
			log.Errorf("Student not found: %v", studentId)
			c.JSON(http.StatusNotFound, response.ResponseV2{
				Success: false,
				Message: "Student with ID " + strconv.Itoa(studentId) + " not found",
			})
			return
		}

		if student.Role != "student" {
			log.Errorf("User is not a student: %v", studentId)
			c.JSON(http.StatusBadRequest, response.ResponseV2{
				Success: false,
				Message: "User with ID " + strconv.Itoa(studentId) + " is not a student",
			})
			return
		}
	}

	if err := ctrl.ClassroomRepo.EnrollStudents(ctx, classroomId, req.StudentIds); err != nil {
		log.Errorf("Failed to enroll students: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to enroll students",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Message: "Students enrolled successfully",
	})
}

// UnenrollStudent removes a student from a classroom
func (ctrl *ClassroomController) UnenrollStudent(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	classroomId, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	studentIdParam := c.Param("student_id")
	studentId, err := strconv.Atoi(studentIdParam)
	if err != nil {
		log.Errorf("Invalid student ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid student ID",
		})
		return
	}

	// Check if classroom exists
	_, err = ctrl.ClassroomRepo.GetClassroomByID(ctx, classroomId)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	if err := ctrl.ClassroomRepo.UnenrollStudent(ctx, classroomId, studentId); err != nil {
		log.Errorf("Failed to unenroll student: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to unenroll student",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Message: "Student unenrolled successfully",
	})
}

// GetStudentsByClassroom retrieves all students in a classroom
func (ctrl *ClassroomController) GetStudentsByClassroom(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	idParam := c.Param("id")
	classroomId, err := strconv.Atoi(idParam)
	if err != nil {
		log.Errorf("Invalid classroom ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid classroom ID",
		})
		return
	}

	// Check if classroom exists
	_, err = ctrl.ClassroomRepo.GetClassroomByID(ctx, classroomId)
	if err != nil {
		log.Errorf("Classroom not found: %v", err)
		c.JSON(http.StatusNotFound, response.ResponseV2{
			Success: false,
			Message: "Classroom not found",
		})
		return
	}

	students, err := ctrl.ClassroomRepo.GetStudentsByClassroom(ctx, classroomId)
	if err != nil {
		log.Errorf("Failed to retrieve students: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to retrieve students",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Data:    response.ToStudentResponseList(students),
	})
}

// GetClassroomsByTeacher retrieves all classrooms for a teacher
func (ctrl *ClassroomController) GetClassroomsByTeacher(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	teacherIdParam := c.Param("teacher_id")
	teacherId, err := strconv.Atoi(teacherIdParam)
	if err != nil {
		log.Errorf("Invalid teacher ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid teacher ID",
		})
		return
	}

	classrooms, err := ctrl.ClassroomRepo.GetClassroomsByTeacher(ctx, teacherId)
	if err != nil {
		log.Errorf("Failed to retrieve classrooms: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to retrieve classrooms",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Data:    response.ToClassroomResponseList(classrooms),
	})
}

// GetClassroomsByStudent retrieves all classrooms for a student
func (ctrl *ClassroomController) GetClassroomsByStudent(c *gin.Context) {
	ctx := correlation.WithReqContext(c)
	log := logger.Logger(ctx)

	studentIdParam := c.Param("student_id")
	studentId, err := strconv.Atoi(studentIdParam)
	if err != nil {
		log.Errorf("Invalid student ID: %v", err)
		c.JSON(http.StatusBadRequest, response.ResponseV2{
			Success: false,
			Message: "Invalid student ID",
		})
		return
	}

	classrooms, err := ctrl.ClassroomRepo.GetClassroomsByStudent(ctx, studentId)
	if err != nil {
		log.Errorf("Failed to retrieve classrooms: %v", err)
		c.JSON(http.StatusInternalServerError, response.ResponseV2{
			Success: false,
			Message: "Failed to retrieve classrooms",
		})
		return
	}

	c.JSON(http.StatusOK, response.ResponseV2{
		Success: true,
		Data:    response.ToClassroomResponseList(classrooms),
	})
}

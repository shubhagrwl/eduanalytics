package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
	"time"
)

type IClassroomsRepository interface {
	CreateClassroom(ctx context.Context, classroom *dto.Classroom) error
	GetClassroom(ctx context.Context, where string) (*dto.Classroom, error)
	GetClassroomByID(ctx context.Context, id int) (*dto.Classroom, error)
	GetClassroomsByTeacher(ctx context.Context, teacherId int) ([]dto.Classroom, error)
	GetClassroomsBySchool(ctx context.Context, schoolId int) ([]dto.Classroom, error)
	UpdateClassroom(ctx context.Context, id int, classroom *dto.Classroom) error
	DeleteClassroom(ctx context.Context, id int) error

	// Student-Classroom operations
	EnrollStudents(ctx context.Context, classroomId int, studentIds []int) error
	UnenrollStudent(ctx context.Context, classroomId int, studentId int) error
	GetStudentsByClassroom(ctx context.Context, classroomId int) ([]dto.User, error)
	GetClassroomsByStudent(ctx context.Context, studentId int) ([]dto.Classroom, error)
	IsStudentEnrolled(ctx context.Context, classroomId int, studentId int) (bool, error)
}

type ClassroomsRepository struct {
	DBService *db.DBService
}

func NewClassroomsRepository(dbService *db.DBService) IClassroomsRepository {
	return &ClassroomsRepository{
		DBService: dbService,
	}
}

func (r *ClassroomsRepository) CreateClassroom(ctx context.Context, classroom *dto.Classroom) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	classroom.CreatedAt = time.Now()

	if err := tx.Table(dto.CLASSROOM_TABLE).Create(classroom).Error; err != nil {
		return err
	}

	tx.Commit()
	return nil
}

func (r *ClassroomsRepository) GetClassroom(ctx context.Context, where string) (*dto.Classroom, error) {
	var classroom dto.Classroom

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where(where).First(&classroom).Error; err != nil {
		return nil, err
	}

	return &classroom, nil
}

func (r *ClassroomsRepository) GetClassroomByID(ctx context.Context, id int) (*dto.Classroom, error) {
	var classroom dto.Classroom

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where("id = ?", id).First(&classroom).Error; err != nil {
		return nil, err
	}

	return &classroom, nil
}

func (r *ClassroomsRepository) GetClassroomsByTeacher(ctx context.Context, teacherId int) ([]dto.Classroom, error) {
	var classrooms []dto.Classroom

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where("teacher_id = ?", teacherId).Find(&classrooms).Error; err != nil {
		return nil, err
	}

	return classrooms, nil
}

func (r *ClassroomsRepository) GetClassroomsBySchool(ctx context.Context, schoolId int) ([]dto.Classroom, error) {
	var classrooms []dto.Classroom

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where("school_id = ?", schoolId).Find(&classrooms).Error; err != nil {
		return nil, err
	}

	return classrooms, nil
}

func (r *ClassroomsRepository) UpdateClassroom(ctx context.Context, id int, classroom *dto.Classroom) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where("id = ?", id).Updates(classroom).Error; err != nil {
		return err
	}

	tx.Commit()
	return nil
}

func (r *ClassroomsRepository) DeleteClassroom(ctx context.Context, id int) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).Where("id = ?", id).Delete(&dto.Classroom{}).Error; err != nil {
		return err
	}

	tx.Commit()
	return nil
}

// Student-Classroom operations

func (r *ClassroomsRepository) EnrollStudents(ctx context.Context, classroomId int, studentIds []int) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	for _, studentId := range studentIds {
		studentClassroom := dto.StudentClassroom{
			StudentId:   studentId,
			ClassroomId: classroomId,
			EnrolledAt:  time.Now(),
		}

		// Use FirstOrCreate to avoid duplicates
		if err := tx.Table(dto.STUDENT_CLASSROOM_TABLE).
			Where("student_id = ? AND classroom_id = ?", studentId, classroomId).
			FirstOrCreate(&studentClassroom).Error; err != nil {
			return err
		}
	}

	tx.Commit()
	return nil
}

func (r *ClassroomsRepository) UnenrollStudent(ctx context.Context, classroomId int, studentId int) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.STUDENT_CLASSROOM_TABLE).
		Where("student_id = ? AND classroom_id = ?", studentId, classroomId).
		Delete(&dto.StudentClassroom{}).Error; err != nil {
		return err
	}

	tx.Commit()
	return nil
}

func (r *ClassroomsRepository) GetStudentsByClassroom(ctx context.Context, classroomId int) ([]dto.User, error) {
	var students []dto.User

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.USER_TABLE).
		Joins("JOIN "+dto.STUDENT_CLASSROOM_TABLE+" ON "+dto.USER_TABLE+".id = "+dto.STUDENT_CLASSROOM_TABLE+".student_id").
		Where(dto.STUDENT_CLASSROOM_TABLE+".classroom_id = ?", classroomId).
		Find(&students).Error; err != nil {
		return nil, err
	}

	return students, nil
}

func (r *ClassroomsRepository) GetClassroomsByStudent(ctx context.Context, studentId int) ([]dto.Classroom, error) {
	var classrooms []dto.Classroom

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.CLASSROOM_TABLE).
		Joins("JOIN "+dto.STUDENT_CLASSROOM_TABLE+" ON "+dto.CLASSROOM_TABLE+".id = "+dto.STUDENT_CLASSROOM_TABLE+".classroom_id").
		Where(dto.STUDENT_CLASSROOM_TABLE+".student_id = ?", studentId).
		Find(&classrooms).Error; err != nil {
		return nil, err
	}

	return classrooms, nil
}

func (r *ClassroomsRepository) IsStudentEnrolled(ctx context.Context, classroomId int, studentId int) (bool, error) {
	var count int

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.STUDENT_CLASSROOM_TABLE).
		Where("student_id = ? AND classroom_id = ?", studentId, classroomId).
		Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

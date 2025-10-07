package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
)

type ISchoolsRepository interface {
	CreateSchool(ctx context.Context, user dto.School) error
	GetSchool(ctx context.Context, where string) (*dto.School, error)
}

type SchoolsRepository struct {
	DBService *db.DBService
}

func NewSchoolsRepository(dbService *db.DBService) ISchoolsRepository {
	return &SchoolsRepository{
		DBService: dbService,
	}
}

func (r *SchoolsRepository) CreateSchool(ctx context.Context, school dto.School) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.SCHOOL_TABLE).Create(&school).Error; err != nil {
		return err
	}

	tx.Commit()

	return nil
}

func (r *SchoolsRepository) GetSchool(ctx context.Context, where string) (*dto.School, error) {
	var school dto.School

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.SCHOOL_TABLE).Where(where).First(&school).Error; err != nil {
		return &school, err
	}

	return &school, nil
}

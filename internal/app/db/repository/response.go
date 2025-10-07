package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
)

type IResponseRepository interface {
	CreateResponse(ctx context.Context, response *dto.Response) error
	GetResponse(ctx context.Context, where string) (*dto.Response, error)
}

type ResponseRepository struct {
	DBService *db.DBService
}

func NewResponseRepository(dbService *db.DBService) IResponseRepository {
	return &ResponseRepository{
		DBService: dbService,
	}
}

func (r *ResponseRepository) CreateResponse(ctx context.Context, response *dto.Response) error {
	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.RESPONSE_TABLE).Create(response).Error; err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (r *ResponseRepository) GetResponse(ctx context.Context, where string) (*dto.Response, error) {
	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)
	var response dto.Response

	if err := tx.Table(dto.RESPONSE_TABLE).Where(where).First(&response).Error; err != nil {
		return &response, err
	}
	return &response, nil
}

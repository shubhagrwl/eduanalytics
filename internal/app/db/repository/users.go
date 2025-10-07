package repository

import (
	"context"
	"eduanalytics/internal/app/constants"
	"eduanalytics/internal/app/db"
	"eduanalytics/internal/app/db/dto"
	"time"
)

type IUsersRepository interface {
	CreateUser(ctx context.Context, user *dto.User) error
	GetUser(ctx context.Context, where string) (*dto.User, error)
	GetUserByEmail(ctx context.Context, email string) (*dto.User, error)
}

type UsersRepository struct {
	DBService *db.DBService
}

func NewUsersRepository(dbService *db.DBService) IUsersRepository {
	return &UsersRepository{
		DBService: dbService,
	}
}

func (r *UsersRepository) CreateUser(ctx context.Context, user *dto.User) error {

	tx := r.DBService.GetDB().Begin()
	defer tx.Rollback()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)
	user.CreatedAt = time.Now()

	if err := tx.Table(dto.USER_TABLE).Create(user).Error; err != nil {
		return err
	}

	tx.Commit()

	return nil
}

func (r *UsersRepository) GetUser(ctx context.Context, where string) (*dto.User, error) {

	var user dto.User

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.USER_TABLE).Where(where).First(&user).Error; err != nil {
		return &user, err
	}

	return &user, nil
}

func (r *UsersRepository) GetUserByEmail(ctx context.Context, email string) (*dto.User, error) {

	var user dto.User

	tx := r.DBService.GetDB()
	tx.LogMode(constants.Config.DatabaseConfig.DB_LOG_MODE)

	if err := tx.Table(dto.USER_TABLE).Where("email = ?", email).First(&user).Error; err != nil {
		return &user, err
	}

	return &user, nil
}

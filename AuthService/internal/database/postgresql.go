package database

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"AuthService/internal/model"
	"AuthService/internal/utils"
)

type postgres_db struct {
	PostgresDB gorm.DB
}

func InitDataBase() *gorm.DB {
	host := utils.GetKeyFromEnv("POSTGRES_HOST")
	user := utils.GetKeyFromEnv("POSTGRES_USER")
	password := utils.GetKeyFromEnv("POSTGRES_PASSWORD")
	db_name := utils.GetKeyFromEnv("POSTGRES_DB")
	port := utils.GetKeyFromEnv("POSTGRES_PORT")
	timezone := utils.GetKeyFromEnv("POSTGRES_TZ")
	ssl_mode := utils.GetKeyFromEnv("POSTGRES_SSL")

	dsn := fmt.Sprintf("host=%v user=%v password=%v dbname=%v port=%v sslmode=%v TimeZone=%v", host, user, password, db_name, port, ssl_mode, timezone)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Errorf("Failed to init DB: %v", err)
	}
	db.AutoMigrate(&model.User{}, &model.Session{})
	return db
}

func NewPostgresDB(db *gorm.DB) *postgres_db {
	postgres := postgres_db{PostgresDB: *db}
	return &postgres
}

func (db *postgres_db) SearchGUID(guid string) error {
	target_guid := &model.User{}
	if err := db.PostgresDB.Where(&model.User{GUID: guid}).First(&target_guid).Error; err != nil {
		log.Errorf("Failed to find guid: %v", err)
		return err
	}

	return nil
}

func (db *postgres_db) DeleteSession(guid string) error {
	if err := db.PostgresDB.Where("user_guid = ?", guid).Delete(&model.Session{}).Error; err != nil {
		log.Errorf("failed to delete session: %v", err)
		return fmt.Errorf("failed to delete session")
	}

	return nil
}
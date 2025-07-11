package database

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"github.com/google/uuid"

	"AuthService/internal/model"
	"AuthService/internal/auth"
	"AuthService/source/utils"
)

type Database interface {
	SearchGUID(guid string) error
	SearchSession(guid string, session_id uint) (*model.Session, error)
	DeleteSession(guid string, session_id uint) error
	AddSession(guid string, refresh_generator auth.RefreshManager, user_agent string, user_ip string) (uint, string, error)
	AddUser() (string, error)
}

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

	time.Sleep(5 * time.Second)
	log.Info("Sleeping")
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

func (db *postgres_db) AddUser() (string, error){
	guid := uuid.New().String()
	user := model.User{GUID: guid}
	result := db.PostgresDB.Create(&user)
	if result.Error != nil {
		log.Errorf("failed to create User: %v", result.Error)
		return "", result.Error
	}

	return guid, nil
}

func (db *postgres_db) SearchGUID(guid string) error {
	target_guid := &model.User{}
	if err := db.PostgresDB.Where("guid = ?", guid).First(&target_guid).Error; err != nil {
		log.Errorf("Failed to find guid: %v", err)
		return err
	}

	return nil
}

func (db *postgres_db) AddSession(guid string, refresh_generator auth.RefreshManager, user_agent string, user_ip string) (uint, string, error) {
	session := model.Session{
		UserGUID:  guid,
		ExpiresAt: time.Now().Unix() + int64(refresh_generator.GetExparationTime()),
		UserIP:    user_ip,
		UserAgent: user_agent,
	}

	refresh, err := refresh_generator.GenerateRefreshToken()
	if err != nil {
		log.Errorf("failed to generate refresh: %v", err)
		return 0, "", err
	}
	refresh_hash, err := utils.GenerateHash(refresh)
	if err != nil {
		log.Errorf("failed to generate hash: %v", err)
		return 0, "", err
	}

	session.Refresh = refresh_hash

	result := db.PostgresDB.Create(&session)
	if result.Error != nil {
		log.Errorf("failed to create session: %v", result.Error)
		return 0, "", result.Error
	}

	return session.ID, refresh, nil
}

func (db *postgres_db) SearchSession(guid string, session_id uint) (*model.Session, error) {
	session := model.Session{}
	err := db.PostgresDB.Where("user_guid = ? AND id = ?", guid, session_id).Find(&session).Error
	if err != nil {
		log.Errorf("Failed to find session: %v", err)
		return nil, err
	}

	return &session, nil
}

func (db *postgres_db) DeleteSession(guid string, session_id uint) error {
	if err := db.PostgresDB.Where("user_guid = ? AND id = ?", guid, session_id).Delete(&model.Session{}).Error; err != nil {
		log.Errorf("failed to delete session: %v", err)
		return fmt.Errorf("failed to delete session")
	}

	return nil
}

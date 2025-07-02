package model

type Session struct {
	ID 			uint 	`gorm:"primaryKey;autoIncrement"`
	UserGUID 	string 	`gorm:"index"`
	Refresh  	string
	ExpiresAt 	int64
	UserIP		string
	UserAgent	string
}

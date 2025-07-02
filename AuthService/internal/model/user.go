package model

type User struct {
	GUID string `json:"guid" gorm:"uniqueIndex"`
}

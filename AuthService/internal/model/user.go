package model

type User struct {
	GUID 		string 		`json:"guid" gorm:"primarykey"`
	Sessions 	[]Session 	`gorm:"foreignKey:UserGUID"`
}

package models

type Role struct {
	Id   uint8 `gorm:"primaryKey;autoIncrement" json:"id"`
	Name string `gorm:"type:varchar(255);unique" json:"name"`

	Users []User `json:"users"`
}
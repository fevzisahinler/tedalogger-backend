package models

type Role struct {
	ID          uint   `gorm:"column:role_id;primaryKey"`
	RoleName    string `gorm:"unique;not null"`
	Description string
	Users       []User       `gorm:"many2many:user_roles;"`
	Permissions []Permission `gorm:"foreignKey:RoleID"`
}

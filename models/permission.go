package models

type Permission struct {
	ID         uint     `gorm:"column:role_resource_id;primaryKey"`
	RoleID     uint     `gorm:"not null"`
	ResourceID uint     `gorm:"not null"`
	CanView    bool     `gorm:"default:false"`
	CanEdit    bool     `gorm:"default:false"`
	Role       Role     `gorm:"foreignKey:RoleID"`
	Resource   Resource `gorm:"foreignKey:ResourceID"`
}

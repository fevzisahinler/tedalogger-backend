package models

type Resource struct {
	ID           uint   `gorm:"column:resource_id;primaryKey"`
	ResourceName string `gorm:"unique;not null"`
	Description  string
	Permissions  []Permission `gorm:"foreignKey:ResourceID"`
}

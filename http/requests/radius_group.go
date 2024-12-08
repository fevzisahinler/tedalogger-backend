package requests

import (
	"github.com/go-playground/validator/v10"
)

type CreateOrUpdateRadiusGroupRequest struct {
	RadiusGroupName       string `gorm:"unique;not null" json:"radiusGroupName"`
	SessionTimeout        int    `json:"session_timeout"`
	IdleTimeout           int    `json:"idle_timeout"`
	SimultaneousUse       int    `json:"simultaneous_use"`
	Bandwidth             string `json:"bandwidth"`
	TimeOfDayRestrictions string `json:"time_of_day_restrictions"`
	Description           string `json:"description"`
}

func (r *CreateOrUpdateRadiusGroupRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

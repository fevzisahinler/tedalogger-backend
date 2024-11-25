package responses

type ErrorResponse struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type SuccessResponse struct {
	Error   bool        `json:"error"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

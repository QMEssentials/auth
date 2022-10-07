package models

type UserCriteria struct {
	Roles      []string `json:"roles"`
	ActiveOnly bool     `json:"activeOnly"`
}

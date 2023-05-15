package models

type AuthzCheck struct {
	BearerToken string `json:"bearerToken"`
	Permission  string `json:"permission"`
}

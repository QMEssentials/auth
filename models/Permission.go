package models

type Permission struct {
	CanonicalName string
	DisplayName   string
	Roles         []string
}

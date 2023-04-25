package models

type CreateUserRequest struct {
	UserID          string   `json:"userId"`
	GivenNames      []string `json:"givenNames"`
	FamilyNames     []string `json:"familyNames"`
	Roles           []string `json:"roles"`
	EmailAddress    string   `json:"emailAddress"`
	InitialPassword string   `json:"initialPassword"`
}

package authorization

import "auth/repositories"

type PermissionsManager struct {
	userRepo *repositories.UserRepository
}

func NewPermissionsManager(userRepo *repositories.UserRepository) *PermissionsManager {
	return &PermissionsManager{userRepo: userRepo}
}

func (pm *PermissionsManager) IsAllowed(userId string, permission string) (bool, error) {
	user, err := pm.userRepo.Select(userId)
	if err != nil {
		return false, err
	}
	operations := pm.GetPermittedOperationsForRoles(user.Roles)
	for _, operation := range operations {
		if operation == permission {
			return true, nil
		}
	}
	return false, nil
}

func (pm *PermissionsManager) GetPermittedOperationsForRoles(roles []string) []string {
	permissions := make(map[string]struct{})
	var placeholder = struct{}{}
	for _, role := range roles {
		if role == "Administrator" {
			permissions["Create a User"] = placeholder
			permissions["Search for Users"] = placeholder
			permissions["Check for Authorization"] = placeholder
			permissions["Create a Product"] = placeholder
			permissions["Search for Products"] = placeholder
			permissions["View a Product"] = placeholder
			permissions["Edit a Product"] = placeholder
		}
		//The idea is to add to this structure as new roles and permissions become available
		//Eventually it should probably become a table or something
	}
	keys := make([]string, 0, len(permissions))
	for k := range permissions {
		keys = append(keys, k)
	}
	return keys
}

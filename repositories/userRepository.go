package repositories

import (
	"auth/models"
	"auth/utilities"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	mongoUtil *utilities.MongoUtil
}

func NewUserRepository(mongoUtil *utilities.MongoUtil) *UserRepository {
	return &UserRepository{mongoUtil}
}

func (ur *UserRepository) Select(id string) (*models.User, error) {
	ctx, client, _, collection, err := ur.mongoUtil.GetMongoDb("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)
	findResult := collection.FindOne(ctx, bson.D{{Key: "userId", Value: id}})
	if findResult.Err() == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("unable to locate user %s", id)
	}
	var user models.User
	err = findResult.Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (ur *UserRepository) List(criteria *models.UserCriteria) (*[]models.User, error) {
	ctx, client, _, collection, err := ur.mongoUtil.GetMongoDb("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)
	//If we do a more complex user search in the future, we'll need to add indexes and
	//do the search as part of the MongoDB find. This initial implementatino is just
	//to support checking if there's an admin user.
	cursor, err := collection.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	matchingUsers := []models.User{}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var user models.User
		cursor.Decode(&user)
		if criteria.ActiveOnly && !user.IsActive {
			continue
		}
		//Roles are an AND search; all specified roles must be present
		for _, targetRole := range criteria.Roles {
			roleFound := false
			for _, userRole := range user.Roles {
				if userRole == targetRole {
					roleFound = true
					break
				}
			}
			if !roleFound {
				continue
			}
		}
		matchingUsers = append(matchingUsers, user)
	}
	return &matchingUsers, nil
}

func (ur *UserRepository) Add(user *models.User) error {
	ctx, client, _, collection, err := ur.mongoUtil.GetMongoDb("users")
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	_, err = collection.InsertOne(ctx, user)
	return err
}

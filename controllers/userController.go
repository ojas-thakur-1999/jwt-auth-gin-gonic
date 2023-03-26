package controllers

import (
	"context"
	"jwt-auth-gin-gonic/database"
	"jwt-auth-gin-gonic/helpers"
	"jwt-auth-gin-gonic/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(hashedPass)
}

func VerifyPassword(inputPassword string, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		// fetch user details from request
		var user models.User
		err := c.BindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			cancel()
			return
		}

		// fetch user details from DB
		var foundUser models.User
		err = userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user with this email_id not found"})
			cancel()
			return
		}

		// verify password
		verified := VerifyPassword(user.Password, foundUser.Password)
		if !verified {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "incorrect email or password"})
			cancel()
			return
		}

		// generate tokens and updatedAt
		token, refreshToken := helpers.GenerateAllTokens(foundUser.Email, foundUser.First_name, foundUser.Last_name, foundUser.User_id, foundUser.User_type)
		updatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		// update user details in DB
		filter := bson.D{
			{Key: "email", Value: foundUser.Email},
		}
		update := bson.D{
			{
				Key: "$set",
				Value: bson.D{
					{Key: "token", Value: token},
					{Key: "refresh_token", Value: refreshToken},
					{Key: "updated_at", Value: updatedAt},
				},
			},
		}
		updateResult, err := userCollection.UpdateOne(ctx, filter, update)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			cancel()
			return
		}
		if updateResult.ModifiedCount < 1 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update token in DB"})
			cancel()
			return
		}

		// return token
		c.JSON(http.StatusOK, token)
	}
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		// parse request body into user object
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			cancel()
			return
		}

		// validate the user object using validations defined in struct definition
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			cancel()
			return
		}

		// check if emil_id already used
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			log.Panic(err)
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email_id already exists"})
		}

		// check if phone number already used
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			log.Panic(err)
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this phone_no already exists"})
		}

		// store hashed password in db
		user.Password = HashPassword(user.Password)

		// prepare some fields in user object
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		user.Token, user.Refresh_token = helpers.GenerateAllTokens(user.Email, user.First_name, user.Last_name, user.User_id, user.User_type)

		// insert user in mongoDB
		insertId, err := userCollection.InsertOne(ctx, user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user object could not be created"})
			cancel()
			return
		}

		c.JSON(http.StatusOK, insertId)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		// only ADMIN users can use this API
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		// obtain pagination params from query
		recordsPerPage, err := strconv.Atoi(c.Query("recordsPerPage"))
		if err != nil || recordsPerPage < 1 {
			recordsPerPage = 10
		}
		pageNo, err := strconv.Atoi(c.Query("pageNo"))
		if err != nil || pageNo < 1 {
			pageNo = 1
		}
		startIdx, err := strconv.Atoi(c.Query("startIdx"))
		if err != nil || startIdx < 1 {
			startIdx = (pageNo - 1) * recordsPerPage
		}

		// define matchStage, groupStage, projectStage for mongoDB aggregation query
		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}}
		projectStage := bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIdx, recordsPerPage}}}},
		}}}

		// make mongoDB aggregate query
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// extract info from result
		var allUsers []bson.M
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

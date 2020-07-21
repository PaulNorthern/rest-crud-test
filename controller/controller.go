package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	//"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	//"github.com/twinj/uuid"
	//"os"
	"rest_auth/config"
	"rest_auth/model"
	//"strconv"
	"time"

	//"io/ioutil"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	// JSON документы в mongoDB хранятся в двоичном формате, называемом BSON.
	// https://habr.com/ru/post/433776/
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	var user model.User
	// Get and read request to json 'body'
	//body, _ := ioutil.ReadAll(r.Body)
	// JSON object convert to GOlang object
	//err := json.Unmarshal(body, &user)

	err := json.NewDecoder(r.Body).Decode(&user)
	var res model.ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	collection, err := config.GetDBCollection()

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	var result model.User
	// Check if User exist
	// D - means order list
	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

			if err != nil {
				res.Error = "Error While Hashing Password, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			user.Password = string(hash)

			// Insert single document
			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Error = "Error While Creating User, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			res.Result = "Registration Successful"
			json.NewEncoder(w).Encode(res)
			return
		}

		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Result = "Username already Exists!!"
	json.NewEncoder(w).Encode(res)
	return
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	var user model.User
	_ = json.NewDecoder(r.Body).Decode(&user)
	//body, _ := ioutil.ReadAll(r.Body)
	//err := json.Unmarshal(body, &user)
	//if err != nil {
	//	log.Fatal(err)
	//}

	collection, err := config.GetDBCollection()

	if err != nil {
		log.Fatal(err)
	}

	// create a value into which the result can be decoded
	var result model.User
	var res model.ResponseResult

	// A pointer to a variable into which the result can be decoded.
	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)

	if err != nil {
		res.Error = "Invalid username"
		json.NewEncoder(w).Encode(res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Error = "Invalid password"
		json.NewEncoder(w).Encode(res)
		return
	}

	// Generate jwt-token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":  result.Username,
		"firstname": result.FirstName,
		"lastname":  result.LastName,
	})

	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		res.Error = "Error while generating token,Try again"
		json.NewEncoder(w).Encode(res)
		return
	}

	result.Token = tokenString
	result.Password = ""

	json.NewEncoder(w).Encode(result)

}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	})
	var result model.User
	var res model.ResponseResult
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result.Username = claims["username"].(string)
		result.FirstName = claims["firstname"].(string)
		result.LastName = claims["lastname"].(string)

		json.NewEncoder(w).Encode(result)
		return
	} else {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

}

func RecieveToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	td := &model.TokenDetails{}
	//td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	//td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	//td.RefreshUuid = uuid.NewV4().String()

	var userid = mux.Vars(r)

	var err error

	//Creating Access Token
	//os.Setenv("ACCESS_SECRET", "jdnfksdmfksd")
	empData, err := json.Marshal(userid)
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	//atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	//atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	td.AccessToken, err = at.SignedString([]byte(empData))
	if err != nil {
		log.Fatal(err)
	}
	//Creating Refresh Token
	//os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")
	rtClaims := jwt.MapClaims{}
	//rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	//rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(empData))
	//if err != nil {
	//	return nil, err
	//}
	//return td, nil


	// Returned JSON response
	//json.NewEncoder(w).Encode(td)
	//return

	var token model.TokenDetails

	//json.NewDecoder(r.Body).Decode(&token)

	//if err != nil {
	//	json.NewEncoder(w).Encode(token)
	//	return
	//}

	collection, err := config.GetDBCollection()

	if err != nil {
		json.NewEncoder(w).Encode(token)
		return
	}

	//var result model.TokenDetails

	//err = collection.FindOne(context.TODO(), bson.D{{"username", token.AccessToken}}).Decode(&result)
	_, err = collection.InsertOne(context.TODO(), td)
	if err != nil {
		json.NewEncoder(w).Encode(token)
		return
	}
	json.NewEncoder(w).Encode(td)
	return
}

func DeleteToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	collection, err := config.GetDBCollection()

	if err != nil {
		log.Fatal(err)
		return
	}

	params := mux.Vars(r)
	
	fmt.Println(params)
	filter := bson.M{"refresh_token": params}
	deleteResult, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Deleted %v documents in the trainers collection\n", deleteResult.DeletedCount)
}

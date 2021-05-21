package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// Build Register handler-http
func Register(w http.ResponseWriter, r *http.Request) {
	db, _ := ConnectDB()
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	defer r.Body.Close()

	data := make(map[string]string)
	if r.Method == http.MethodPost {
		// Read Data From Body
		// read req body
		bytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// decode the body
		err = json.Unmarshal(bytes, &data)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Check that UserName IS Not Taken
		var user = User{}
		res := db.Where("user_name = ?", data["username"]).Find(&user)
		if res.RowsAffected == 1 && data["username"] == user.UserName {
			respondWithError(w, http.StatusInternalServerError, "User Name is already taken")
			return
		}
		// Check Email is not Taken
		res = db.Where("email = ?", data["email"]).Find(&user)
		if res.RowsAffected == 1 && data["email"] == user.Email {
			respondWithError(w, http.StatusInternalServerError, "Email is already taken")
			return
		}

		user.Email = data["email"]
		user.UserName = data["username"]

		// setup password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
		// CreateRecord over UserTable
		db.Create(&User{
			UserName: user.UserName,
			Email:    user.Email,
			Password: hashedPassword})

		// return Ok Status
		respondWithJson(w, http.StatusCreated, struct {
			Ok string `json:"ok"`
		}{
			Ok: "Success",
		})
	}
}

// Build sign-in http handler
func Login(w http.ResponseWriter, r *http.Request) {
	db, _ := ConnectDB()
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	defer r.Body.Close()

	data := make(map[string]string)
	if r.Method == http.MethodPost {
		// Read Data From Body
		// read req body
		bytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// decode the body
		err = json.Unmarshal(bytes, &data)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		username := data["username"]
		password := data["password"]

		var user User
		// Check User Is already found
		res := db.Where("user_name = ?", username).Find(&user)
		if res.Error != nil || res.RowsAffected == 0 {
			respondWithError(w, http.StatusInternalServerError, "username or password are wrong")
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
			respondWithError(w, http.StatusInternalServerError, "username or password are wrong")
			return
		}

		// Create Session Record with
		// Create New UUID
		sessionID, _ := uuid.NewV4()
		db.Create(&Session{
			ID:           sessionID,
			UserID:       user.ID,
			LastActivity: time.Now(),
		})

		// Setup a Cookie with
		expiration := time.Now().Add(time.Minute * 30)

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionID.String(),
			Expires:  expiration,
			HttpOnly: true,
		})

		// Return Ok status
		respondWithJson(w, http.StatusOK, struct {
			Ok string `json:"ok"`
		}{
			Ok: "Success, Welcome back our friend !",
		})
	}
}

// Build logout handler
func Logout(w http.ResponseWriter, r *http.Request) {
	db, _ := ConnectDB()
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	// Check if he is already logged in
	ok, sessionID := alreadyLoggedIn(r)
	if !ok {
		respondWithError(w, 205, "You 're not already logged in")
		return
	}

	// delete the session record
	var session Session
	db.Where("id = ?", sessionID).Delete(&session)

	// delete cookie
	c := &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	// Return Ok status
	respondWithJson(w, http.StatusOK, struct {
		Ok string `json:"ok"`
	}{
		Ok: "Success, Good bye our friend !",
	})
}

func alreadyLoggedIn(r *http.Request) (bool, string) {
	db, _ := ConnectDB()
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	cookie, err := r.Cookie("session")
	if err != nil {
		return false, ""
	}
	// check that cookie value which is sessionID is already available
	var session Session
	res := db.Where("id = ?", cookie.Value).Where("user_id is not null").Find(&session)
	if res.Error != nil {
		return false, ""
	}
	return true, cookie.Value
}

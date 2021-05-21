package main

import (
	"database/sql"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// User Model
type User struct {
	ID       int `gorm:"primarykey"`
	UserName string
	Email    string
	Password []byte
	Sessions []Session
}

// Session Model
type Session struct {
	ID           uuid.UUID
	LastActivity time.Time
	UserID       int
}

// Config Db
func ConnectDB() (db *gorm.DB, err error) {
	// dsn := "host=localhost user=myuser dbname=golang_tutorial port=5432"
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  `user=postgres password=a12345 dbname=DBTEMP port=5432 sslmode=disable`,
		PreferSimpleProtocol: true, // disables implicit prepared statement usage. By default pgx automatically uses the extended protocol
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "DEV.", // schema name
			SingularTable: false,
		}})
	return
}

// instantiate router
func HttpRouter() {
	r := mux.NewRouter()
	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/logout", Logout).Methods("POST")
	http.ListenAndServe(":9090", r)
}

func main() {
	var sqlDB *sql.DB
	var db *gorm.DB
	{
		var err error
		db, err = ConnectDB()
		if err != nil {
			os.Exit(-1)
		}
		sqlDB, _ = db.DB()
		//sqlDB.Exec(`set search_path='DEV'`)
	}
	defer sqlDB.Close()
	db.AutoMigrate(&User{}, &Session{})
	HttpRouter()
}

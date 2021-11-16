package app

import (
	"banking-auth/domain"
	"banking-auth/service"
	"fmt"
	"github.com/barnettt/banking-lib/logger"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"log"
	"net/http"
	"os"
	"time"
)

const contentTypeJson string = "application/json"
const contentTypeXml string = "application/xml"

func StartApp() {
	if os.Getenv("SERVER_PORT") == "" ||
		os.Getenv("SERVER_HOST") == "" ||
		os.Getenv("DB_HOST") == "" ||
		os.Getenv("DB_PORT") == "" ||
		os.Getenv("DB_USER") == "" ||
		os.Getenv("DB_PASSWD") == "" ||
		os.Getenv("DB_PROTOCOL") == "" ||
		os.Getenv("DB_NAME") == "" ||
		os.Getenv("DB_DRIVER_NAME") == "" {
		logger.Error("Environment variables are undefined ... ")
		log.Fatal("Environment variables are undefined ... ")
	}
	// create db connection pool
	var dbClient = getDbClient()
	// create a new multiplexer
	// print("creating mux\n ")
	logger.Info("creating mux ")
	// mux := http.NewServeMux()

	router := mux.NewRouter()
	// Wiring app components
	repo := domain.NewUserRepository(dbClient)
	handler := UserHandler{service.NewUserService(repo, service.NewTokenService(repo), domain.GetUserRolePermissions())}

	// define all the routes

	router.HandleFunc("/customers/login", handler.GetUserByUserName).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", handler.VerifyRequest).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", handler.Refresh).Methods(http.MethodPost)

	// log any error to fatal
	// print("starting listener ..... \n")
	port := os.Getenv("SERVER_PORT")
	host := os.Getenv("SERVER_HOST")
	logger.Info("starting listener ..... on server port : " + port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router))

}

//func getTransactionManager(client *sqlx.DB) db.TxManager {
//	return db.NewTxManager(client)
//}

func getDbClient() *sqlx.DB {
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWD")
	dbName := os.Getenv("DB_NAME")
	dbProtocol := os.Getenv("DB_PROTOCOL")
	dbDrivername := os.Getenv("DB_DRIVER_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	client, err := sqlx.Open(fmt.Sprintf("%s", dbDrivername), fmt.Sprintf("%s:%s@%s(%s:%s)/%s?parseTime=true", user, password, dbProtocol, dbHost, dbPort, dbName))
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}

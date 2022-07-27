package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
	"ws/entity"
	"ws/service"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const PORT = ":8080"
const USERNAME = "bambang111"
const PASSWORD = "bambangs"
const secretkey = "jwtsecretkey111"

type Status struct {
	Water int `json:"water"`
	Wind  int `json:"wind"`
}

type Weather struct {
	Status  Status `json:"status"`
	Remarks string `json:"remarks"`
}

var data Weather

func dbConn() *sql.DB {
	db, err := sql.Open("mysql", "root:admin123@tcp(127.0.0.1:3306)/hello?parseTime=true")
	if err != nil {
		panic(err)
	}
	return db
}

var db *sql.DB

func main() {
	db = dbConn()
	defer db.Close()
	r := mux.NewRouter()
	userRoutes := r.PathPrefix("/users").Subrouter()
	userRoutes.HandleFunc("", UserHandler)
	userRoutes.HandleFunc("/{Id}", UserHandler)
	userRoutes.HandleFunc("/{Id}", UserHandler)
	userRoutes.HandleFunc("/users-url", GetUserFromAPI)
	userRoutes.Use(MiddlewareAuth)

	r.HandleFunc("/register", RegisterHandler)
	r.HandleFunc("/login", Login).Methods("POST")
	go RNG()
	r.HandleFunc("/assignment3", TriggerWeather)
	http.Handle("/", r)
	http.ListenAndServe(PORT, nil)
}

//Handler functions
func greet(w http.ResponseWriter, r *http.Request) {
	msg := "Hello world"
	fmt.Fprint(w, msg)
}

const HtmlPath = "static/web.html"
const JsonPath = "static/weather.json"

func TriggerWeather(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	file, _ := ioutil.ReadFile(JsonPath)
	json.Unmarshal(file, &data)
	template, _ := template.ParseFiles(HtmlPath)
	tempData := Weather{
		Status: Status{
			Water: data.Status.Water,
			Wind:  data.Status.Wind,
		},
		Remarks: data.Remarks,
	}
	template.Execute(w, tempData)

}

func Login(w http.ResponseWriter, r *http.Request) {
	var authDetails entity.Authentication
	err := json.NewDecoder(r.Body).Decode(&authDetails)

	service.NewUserService().Register()

	if err != nil {
		var err entity.Error
		err = SetError(err, "Error in reading auth")
		json.NewEncoder(w).Encode(err)
		return
	}

	var user entity.User

	query := "SELECT username, password from user where username = ?"
	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()
	fmt.Printf(authDetails.Username)
	rows := db.QueryRowContext(ctx, query, authDetails.Username)
	if err != nil {
		panic(err)
	}
	rows.Scan(&user.Username, &user.Password)

	check := CheckPasswordHash(authDetails.Password, user.Password)
	if !check {
		var err entity.Error
		err = SetError(err, "username or password is incorrect")
		json.NewEncoder(w).Encode(err)
		return
	}
	validToken, err := GenerateJWT(user.Username)
	if err != nil {
		var err entity.Error
		err = SetError(err, "Failed to generate token")
		json.NewEncoder(w).Encode(err)
		return
	}

	var token entity.Token
	token.Username = user.Username
	token.TokenString = validToken
	json.NewEncoder(w).Encode(token)
	return
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func UserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	params := mux.Vars(r)
	Id := params["Id"]
	if r.Method == "GET" {
		if Id != "" {
			tempId, _ := strconv.Atoi(Id)
			GetUserById(w, r, tempId)
		} else {
			GetAllUser(w, r)
		}
	}
	if r.Method == "DELETE" {
		tempId, _ := strconv.Atoi(Id)
		DeleteUser(w, r, tempId)
	}

	if r.Method == "PUT" {
		tempId, _ := strconv.Atoi(Id)
		UpdateUser(w, r, tempId)
	}
}
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		AddUser(w, r)
	}
}

func GetUserById(w http.ResponseWriter, r *http.Request, id int) {
	var user entity.User
	query := "SELECT ID, USERNAME, PASSWORD, EMAIL, AGE FROM USER WHERE ID = ?"
	row := db.QueryRow(query, id)
	err := row.Scan(&user.Id, &user.Username, &user.Password, &user.Email, &user.Age)
	if err != nil {
		panic(err)
	}
	jsonData, _ := json.Marshal(user)
	w.Write(jsonData)
}

func GetAllUser(w http.ResponseWriter, r *http.Request) {
	results := []entity.User{}
	data, err := db.Query("SELECT id, username, password, email, age FROM USER")
	if err != nil {
		panic(err)
	}
	for data.Next() {
		var user entity.User
		err := data.Scan(&user.Id, &user.Username, &user.Password, &user.Email, &user.Age)
		if err != nil {
			panic(err)
		}
		results = append(results, user)
	}
	test, _ := json.Marshal(results)
	w.Write(test)
}

func DeleteUser(w http.ResponseWriter, r *http.Request, id int) {
	query := "DELETE FROM USER WHERE id = ?"
	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()
	stmt, err := db.PrepareContext(ctx, query)
	res, err := stmt.ExecContext(ctx, id)
	if err != nil {
		ResponseWriter(w, 504, "Internal server error")
	}
	res.LastInsertId()
	res.RowsAffected()
	ResponseWriter(w, 200, "User deleted successfully")
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var user entity.User
	if err := decoder.Decode(&user); err != nil {
		ResponseWriter(w, 504, "Error decoding body")
		return
	} else {
		user.Password, err = GeneratehashPassword(user.Password)
		if err != nil {
			log.Fatalln("error in password hash")
			ResponseWriter(w, 504, "Error hashing password")
		}
		query := "INSERT INTO USER (username, password, email, age, createdat, updatedat) VALUES(?,?,?,?,?,?)"
		ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := db.PrepareContext(ctx, query)
		_, err = stmt.ExecContext(ctx, user.Username, user.Password, user.Email, user.Age, time.Now(), nil)
		if err != nil {
			log.Fatal(err)
		}
		ResponseWriter(w, 200, "User added successfully")
	}
}

func UpdateUser(w http.ResponseWriter, r *http.Request, id int) {
	decoder := json.NewDecoder(r.Body)
	var temp entity.User
	if err := decoder.Decode(&temp); err != nil {
		ResponseWriter(w, 504, "Internal server error")
		return
	}
	query := "update user set Username = ?, Password = ?, Email = ?, Age = ?, UpdatedAt = ? where Id = ?"
	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()
	if stmt, err := db.PrepareContext(ctx, query); err != nil {
		log.Fatal(err)
		if _, err := stmt.ExecContext(ctx, temp.Username, temp.Password, temp.Email, temp.Age, time.Now(), id); err != nil {
			ResponseWriter(w, 504, "Internal server error")
		}
	}

	ResponseWriter(w, 200, "User updated successfully")

}

func GetUserFromAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Accept", "application/json")
	w.Header().Add("Content-Type", "application/json")
	client := &http.Client{}
	if r.Method == "GET" {
		req, err := http.Get("https://random-data-api.com/api/users/random_user?size=10")
		if err != nil {
			log.Fatalln(err)
		}
		resp, err := client.Do(req.Request)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		type Coordinates struct {
			Latitude  float64 `json:"lat"`
			Longitude float64 `json:"lng"`
		}

		type Address struct {
			City          string      `json:"city"`
			StreetName    string      `json:"street_name"`
			StreetAddress string      `json:"street_address"`
			ZipCode       string      `json:"zip_code"`
			State         string      `json:"state"`
			Country       string      `json:"country"`
			Coordinates   Coordinates `json:"coordinates"`
		}
		type User struct {
			Id         int      `json:"id"`
			Uid        string   `json:"uid"`
			First_name string   `json:"first_name"`
			Last_name  string   `json:"last_name"`
			Username   string   `json:"username"`
			Address    *Address `json:"address"`
		}

		var user []User
		json.NewDecoder(resp.Body).Decode(&user)
		jsonData, err := json.Marshal(&user)
		if err != nil {
			log.Fatal(err)
		}

		w.Write(jsonData)
	}
}

//Middleware
func MiddlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, ok := extractTokenFromAuthHeader(r.Header.Get("Authorization"))

		if !ok {
			var err entity.Error
			err = SetError(err, "No Token Found")
			json.NewEncoder(w).Encode(err)
			return
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretkey), nil
		})
		if err != nil {
			var err entity.Error
			err = SetError(err, "Error parsing token")
			json.NewEncoder(w).Encode(err)
			return
		}
		var tm time.Time
		switch exp := claims["exp"].(type) {
		case float64:
			tm = time.Unix(int64(exp), 0)
		case json.Number:
			v, _ := exp.Int64()
			tm = time.Unix(v, 0)
		}

		if tm.Before(time.Now()) {
			var err entity.Error
			err = SetError(err, "Token expired")
			json.NewEncoder(w).Encode(err)
			return
		}
		next.ServeHTTP(w, r)

	})

}

//Helper functions
func extractTokenFromAuthHeader(val string) (token string, ok bool) {
	authHeaderParts := strings.Split(val, " ")
	if len(authHeaderParts) != 2 || !strings.EqualFold(authHeaderParts[0], "bearer") {
		return "", false
	}

	return authHeaderParts[1], true
}
func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func GenerateJWT(username string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func SetError(err entity.Error, message string) entity.Error {
	err.IsError = true
	err.Message = message
	return err
}

func ResponseWriter(w http.ResponseWriter, status int, message string) {
	var response entity.Response
	response.Status = status
	response.Message = message
	responseJson, _ := json.Marshal(response)
	w.Write(responseJson)
}

func RNG() error {
	for {

		data.Status.Water = rand.Intn(100-1) + 1
		data.Status.Wind = rand.Intn(100-1) + 1
		if (data.Status.Water >= 6 && data.Status.Water <= 8) || (data.Status.Water >= 7 && data.Status.Wind <= 15) {
			data.Remarks = "siaga"
		} else if data.Status.Water > 8 || data.Status.Wind > 15 {
			data.Remarks = "bahaya"
		}
		GenerateWeatherStatusFile(data)
		time.Sleep(15 * time.Second)
		return nil
	}
}

func GenerateWeatherStatusFile(data Weather) {

	file, _ := json.MarshalIndent(data, "", "    ")

	_ = ioutil.WriteFile("static/weather.json", file, 0644)
}

func Sum(a1, a2 int) int {
	return a1 + a2
}

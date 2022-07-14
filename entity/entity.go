package entity

import "time"

type User struct {
	Id        int
	Username  string
	Email     string
	Password  string
	Age       int
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Authentication struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Token struct {
	Username    string `json:"username"`
	TokenString string `json:"token"`
}

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

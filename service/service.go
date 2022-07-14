package service

import (
	"ws/entity"
)

type UserServiceIface interface {
	Register(user *entity.User) *entity.User
}

type UserSvc struct{}

func NewUserService() UserServiceIface {
	return &UserSvc{}
}

func (u *UserSvc) Register(user *entity.User) *entity.User {
	return user
}

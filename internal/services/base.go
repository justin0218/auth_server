package services

import "auth_server/store"

type baseService struct {
	Redis  store.Redis
	Config store.Config
}

package api

import (
	"auth_server/api/proto"
	"auth_server/internal/services"
	"auth_server/store"
	"fmt"
	"google.golang.org/grpc"
	"net"
)

type authSvr struct {
	userService services.UserService
	conf        store.Config
}

func GrpcServer() {
	conf := new(store.Config)
	lis, err := net.Listen("tcp", fmt.Sprintf("%s", conf.Get().Etcd.Key))
	if err != nil {
		panic(err)
	}
	var opts []grpc.ServerOption
	svr := grpc.NewServer(opts...)
	proto.RegisterAuthServer(svr, &authSvr{})
	err = svr.Serve(lis)
	if err != nil {
		panic(err)
	}
}

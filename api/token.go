package api

import (
	"auth_server/api/proto"
	"auth_server/pkg/jwt"
	"context"
	"fmt"
)

func (s *authSvr) CreateToken(ctx context.Context, req *proto.CreateTokenReq) (ret *proto.CreateTokenRes, err error) {
	ret = new(proto.CreateTokenRes)
	if req.TokenType == proto.TokenType_ADMIN {
		token, e := jwt.CreateToken(req.Uid, s.conf.Get().Jwt.AdminSecret, s.conf.Get().Jwt.AdminTtl)
		if e != nil {
			err = e
			return
		}
		ret.Token = token
		return
	} else if req.TokenType == proto.TokenType_CLIENT {
		token, e := jwt.CreateToken(req.Uid, s.conf.Get().Jwt.ClientSecret, s.conf.Get().Jwt.ClientTtl)
		if e != nil {
			err = e
			return
		}
		ret.Token = token
		return
	}
	err = fmt.Errorf("token类型错误")
	return
}

func (s *authSvr) VerifyToken(ctx context.Context, req *proto.VerifyTokenReq) (ret *proto.VerifyTokenRes, err error) {
	ret = new(proto.VerifyTokenRes)
	if req.TokenType == proto.TokenType_ADMIN {
		uid, e := jwt.VerifyToken(req.Token, s.conf.Get().Jwt.AdminSecret)
		if e != nil {
			ret.TokenError = proto.TokenError_EXPIRED
			return
		}
		if uid != req.Uid {
			ret.TokenError = proto.TokenError_USER_MATCH
			return
		}
		ret.Uid = uid
		return
	} else if req.TokenType == proto.TokenType_CLIENT {
		uid, e := jwt.VerifyToken(req.Token, s.conf.Get().Jwt.ClientSecret)
		if e != nil {
			err = e
			ret.TokenError = proto.TokenError_EXPIRED
			return
		}
		if uid != req.Uid {
			ret.TokenError = proto.TokenError_USER_MATCH
			return
		}
		ret.Uid = uid
		return ret, nil
	}
	err = fmt.Errorf("token类型错误")
	return
}

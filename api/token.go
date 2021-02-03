package api

import (
	"auth_server/pkg/jwt"
	"context"
)

func (s *authSvr) CreateToken(ctx context.Context, req *CreateTokenReq) (*CreateTokenRes, error) {
	ret := &CreateTokenRes{Code: 400}
	if req.TokenType == TokenType_ADMIN {
		token, e := jwt.CreateToken(req.Uid, s.conf.Get().Jwt.AdminSecret, s.conf.Get().Jwt.AdminTtl)
		if e != nil {
			ret.Msg = e.Error()
			return ret, nil
		}
		ret.Code = 200
		ret.Token = token
		return ret, nil
	} else if req.TokenType == TokenType_CLIENT {
		token, e := jwt.CreateToken(req.Uid, s.conf.Get().Jwt.ClientSecret, s.conf.Get().Jwt.ClientTtl)
		if e != nil {
			ret.Msg = e.Error()
			return ret, nil
		}
		ret.Code = 200
		ret.Token = token
		return ret, nil
	}
	ret.Msg = "token类型错误"
	return ret, nil
}

func (s *authSvr) VerifyToken(ctx context.Context, req *VerifyTokenReq) (*VerifyTokenRes, error) {
	ret := &VerifyTokenRes{Code: 400}
	if req.TokenType == TokenType_ADMIN {
		uid, e := jwt.VerifyToken(req.Token, s.conf.Get().Jwt.AdminSecret)
		if e != nil {
			ret.Msg = e.Error()
			return ret, nil
		}
		if uid != req.Uid {
			ret.Msg = "token无效"
			return ret, nil
		}
		ret.Code = 200
		ret.Uid = uid
		return ret, nil
	} else if req.TokenType == TokenType_CLIENT {
		uid, e := jwt.VerifyToken(req.Token, s.conf.Get().Jwt.ClientSecret)
		if e != nil {
			ret.Msg = e.Error()
			return ret, nil
		}
		if uid != req.Uid {
			ret.Msg = "token无效"
			return ret, nil
		}
		ret.Code = 200
		ret.Uid = uid
		return ret, nil
	}
	ret.Msg = "token类型错误"
	return ret, nil
}

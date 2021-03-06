// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/proto/proto.proto

package proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type TokenType int32

const (
	TokenType_ADMIN  TokenType = 0
	TokenType_CLIENT TokenType = 1
)

var TokenType_name = map[int32]string{
	0: "ADMIN",
	1: "CLIENT",
}

var TokenType_value = map[string]int32{
	"ADMIN":  0,
	"CLIENT": 1,
}

func (x TokenType) String() string {
	return proto.EnumName(TokenType_name, int32(x))
}

func (TokenType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{0}
}

type TokenError int32

const (
	TokenError_EXPIRED    TokenError = 0
	TokenError_USER_MATCH TokenError = 1
)

var TokenError_name = map[int32]string{
	0: "EXPIRED",
	1: "USER_MATCH",
}

var TokenError_value = map[string]int32{
	"EXPIRED":    0,
	"USER_MATCH": 1,
}

func (x TokenError) String() string {
	return proto.EnumName(TokenError_name, int32(x))
}

func (TokenError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{1}
}

type CreateTokenReq struct {
	Uid                  int64     `protobuf:"varint,1,opt,name=uid,proto3" json:"uid,omitempty"`
	TokenType            TokenType `protobuf:"varint,2,opt,name=token_type,json=tokenType,proto3,enum=TokenType" json:"token_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *CreateTokenReq) Reset()         { *m = CreateTokenReq{} }
func (m *CreateTokenReq) String() string { return proto.CompactTextString(m) }
func (*CreateTokenReq) ProtoMessage()    {}
func (*CreateTokenReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{0}
}

func (m *CreateTokenReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateTokenReq.Unmarshal(m, b)
}
func (m *CreateTokenReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateTokenReq.Marshal(b, m, deterministic)
}
func (m *CreateTokenReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateTokenReq.Merge(m, src)
}
func (m *CreateTokenReq) XXX_Size() int {
	return xxx_messageInfo_CreateTokenReq.Size(m)
}
func (m *CreateTokenReq) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateTokenReq.DiscardUnknown(m)
}

var xxx_messageInfo_CreateTokenReq proto.InternalMessageInfo

func (m *CreateTokenReq) GetUid() int64 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func (m *CreateTokenReq) GetTokenType() TokenType {
	if m != nil {
		return m.TokenType
	}
	return TokenType_ADMIN
}

type CreateTokenRes struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateTokenRes) Reset()         { *m = CreateTokenRes{} }
func (m *CreateTokenRes) String() string { return proto.CompactTextString(m) }
func (*CreateTokenRes) ProtoMessage()    {}
func (*CreateTokenRes) Descriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{1}
}

func (m *CreateTokenRes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateTokenRes.Unmarshal(m, b)
}
func (m *CreateTokenRes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateTokenRes.Marshal(b, m, deterministic)
}
func (m *CreateTokenRes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateTokenRes.Merge(m, src)
}
func (m *CreateTokenRes) XXX_Size() int {
	return xxx_messageInfo_CreateTokenRes.Size(m)
}
func (m *CreateTokenRes) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateTokenRes.DiscardUnknown(m)
}

var xxx_messageInfo_CreateTokenRes proto.InternalMessageInfo

func (m *CreateTokenRes) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type VerifyTokenReq struct {
	Uid                  int64     `protobuf:"varint,1,opt,name=uid,proto3" json:"uid,omitempty"`
	TokenType            TokenType `protobuf:"varint,2,opt,name=token_type,json=tokenType,proto3,enum=TokenType" json:"token_type,omitempty"`
	Token                string    `protobuf:"bytes,3,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *VerifyTokenReq) Reset()         { *m = VerifyTokenReq{} }
func (m *VerifyTokenReq) String() string { return proto.CompactTextString(m) }
func (*VerifyTokenReq) ProtoMessage()    {}
func (*VerifyTokenReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{2}
}

func (m *VerifyTokenReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyTokenReq.Unmarshal(m, b)
}
func (m *VerifyTokenReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyTokenReq.Marshal(b, m, deterministic)
}
func (m *VerifyTokenReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyTokenReq.Merge(m, src)
}
func (m *VerifyTokenReq) XXX_Size() int {
	return xxx_messageInfo_VerifyTokenReq.Size(m)
}
func (m *VerifyTokenReq) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyTokenReq.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyTokenReq proto.InternalMessageInfo

func (m *VerifyTokenReq) GetUid() int64 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func (m *VerifyTokenReq) GetTokenType() TokenType {
	if m != nil {
		return m.TokenType
	}
	return TokenType_ADMIN
}

func (m *VerifyTokenReq) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type VerifyTokenRes struct {
	TokenError           TokenError `protobuf:"varint,1,opt,name=token_error,json=tokenError,proto3,enum=TokenError" json:"token_error,omitempty"`
	Uid                  int64      `protobuf:"varint,2,opt,name=uid,proto3" json:"uid,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *VerifyTokenRes) Reset()         { *m = VerifyTokenRes{} }
func (m *VerifyTokenRes) String() string { return proto.CompactTextString(m) }
func (*VerifyTokenRes) ProtoMessage()    {}
func (*VerifyTokenRes) Descriptor() ([]byte, []int) {
	return fileDescriptor_ef32c37ea206d67b, []int{3}
}

func (m *VerifyTokenRes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyTokenRes.Unmarshal(m, b)
}
func (m *VerifyTokenRes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyTokenRes.Marshal(b, m, deterministic)
}
func (m *VerifyTokenRes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyTokenRes.Merge(m, src)
}
func (m *VerifyTokenRes) XXX_Size() int {
	return xxx_messageInfo_VerifyTokenRes.Size(m)
}
func (m *VerifyTokenRes) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyTokenRes.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyTokenRes proto.InternalMessageInfo

func (m *VerifyTokenRes) GetTokenError() TokenError {
	if m != nil {
		return m.TokenError
	}
	return TokenError_EXPIRED
}

func (m *VerifyTokenRes) GetUid() int64 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func init() {
	proto.RegisterEnum("TokenType", TokenType_name, TokenType_value)
	proto.RegisterEnum("TokenError", TokenError_name, TokenError_value)
	proto.RegisterType((*CreateTokenReq)(nil), "create_token_req")
	proto.RegisterType((*CreateTokenRes)(nil), "create_token_res")
	proto.RegisterType((*VerifyTokenReq)(nil), "verify_token_req")
	proto.RegisterType((*VerifyTokenRes)(nil), "verify_token_res")
}

func init() { proto.RegisterFile("api/proto/proto.proto", fileDescriptor_ef32c37ea206d67b) }

var fileDescriptor_ef32c37ea206d67b = []byte{
	// 285 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xd1, 0x4b, 0xc3, 0x30,
	0x10, 0xc6, 0xdb, 0xcd, 0x6e, 0xf4, 0x3a, 0x4a, 0x76, 0x28, 0x8c, 0x3d, 0x8d, 0xfa, 0x52, 0x0a,
	0x56, 0xa8, 0xe0, 0xfb, 0xdc, 0x0a, 0x16, 0xdc, 0x18, 0x59, 0x05, 0xf1, 0xa5, 0x54, 0xcd, 0xb0,
	0x08, 0xb6, 0xa6, 0xd9, 0xa0, 0xff, 0xbd, 0x34, 0x41, 0x17, 0xd7, 0x57, 0x5f, 0x2e, 0x77, 0x5f,
	0xc8, 0xfd, 0xbe, 0x5c, 0x02, 0x17, 0x79, 0x55, 0x5c, 0x57, 0xbc, 0x14, 0xa5, 0x8a, 0xa1, 0x8c,
	0xde, 0x06, 0xc8, 0x2b, 0x67, 0xb9, 0x60, 0x99, 0x28, 0x3f, 0xd8, 0x67, 0xc6, 0xd9, 0x17, 0x12,
	0xe8, 0xef, 0x8b, 0xb7, 0x89, 0x39, 0x33, 0xfd, 0x3e, 0x6d, 0x53, 0x0c, 0x00, 0xd4, 0xb6, 0x68,
	0x2a, 0x36, 0xe9, 0xcd, 0x4c, 0xdf, 0x8d, 0x9c, 0xf0, 0x28, 0x51, 0x5b, 0xe6, 0x69, 0x53, 0x31,
	0xcf, 0xef, 0x74, 0xac, 0xf1, 0x1c, 0x2c, 0x59, 0xc8, 0x9e, 0x36, 0x55, 0x85, 0xb7, 0x03, 0x72,
	0x60, 0xbc, 0xd8, 0x35, 0xff, 0xc5, 0x3e, 0x72, 0xfa, 0x3a, 0x67, 0xdb, 0xe1, 0xd4, 0x78, 0x05,
	0x8e, 0x2a, 0x18, 0xe7, 0x25, 0x97, 0x3c, 0x37, 0x1a, 0x85, 0x9a, 0x46, 0x15, 0x36, 0x6e, 0xf3,
	0x1f, 0x5b, 0xbd, 0x5f, 0x5b, 0xc1, 0xa5, 0x6e, 0x0b, 0x6d, 0xb0, 0xe6, 0xcb, 0x55, 0xb2, 0x26,
	0x06, 0x02, 0x0c, 0x16, 0x0f, 0x49, 0xbc, 0x4e, 0x89, 0x19, 0x04, 0x7f, 0x28, 0xe8, 0xc0, 0x30,
	0x7e, 0xda, 0x24, 0x34, 0x5e, 0x12, 0x03, 0x5d, 0x80, 0xc7, 0x6d, 0x4c, 0xb3, 0xd5, 0x3c, 0x5d,
	0xdc, 0x13, 0x33, 0x3a, 0xc0, 0x59, 0xbe, 0x17, 0xef, 0x78, 0x0b, 0x23, 0x7d, 0x7e, 0x38, 0x0e,
	0x4f, 0x1f, 0x68, 0xda, 0x91, 0x6a, 0xcf, 0x68, 0xcf, 0xe9, 0xb7, 0xc4, 0x71, 0x78, 0x3a, 0xdc,
	0x69, 0x47, 0xaa, 0x3d, 0xe3, 0x6e, 0xf8, 0x6c, 0xc9, 0xaf, 0xf0, 0x32, 0x90, 0xcb, 0xcd, 0x77,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xef, 0xc9, 0x53, 0x2a, 0x2a, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthClient is the client API for Auth service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthClient interface {
	CreateToken(ctx context.Context, in *CreateTokenReq, opts ...grpc.CallOption) (*CreateTokenRes, error)
	VerifyToken(ctx context.Context, in *VerifyTokenReq, opts ...grpc.CallOption) (*VerifyTokenRes, error)
}

type authClient struct {
	cc *grpc.ClientConn
}

func NewAuthClient(cc *grpc.ClientConn) AuthClient {
	return &authClient{cc}
}

func (c *authClient) CreateToken(ctx context.Context, in *CreateTokenReq, opts ...grpc.CallOption) (*CreateTokenRes, error) {
	out := new(CreateTokenRes)
	err := c.cc.Invoke(ctx, "/auth/create_token", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) VerifyToken(ctx context.Context, in *VerifyTokenReq, opts ...grpc.CallOption) (*VerifyTokenRes, error) {
	out := new(VerifyTokenRes)
	err := c.cc.Invoke(ctx, "/auth/verify_token", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServer is the server API for Auth service.
type AuthServer interface {
	CreateToken(context.Context, *CreateTokenReq) (*CreateTokenRes, error)
	VerifyToken(context.Context, *VerifyTokenReq) (*VerifyTokenRes, error)
}

// UnimplementedAuthServer can be embedded to have forward compatible implementations.
type UnimplementedAuthServer struct {
}

func (*UnimplementedAuthServer) CreateToken(ctx context.Context, req *CreateTokenReq) (*CreateTokenRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateToken not implemented")
}
func (*UnimplementedAuthServer) VerifyToken(ctx context.Context, req *VerifyTokenReq) (*VerifyTokenRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyToken not implemented")
}

func RegisterAuthServer(s *grpc.Server, srv AuthServer) {
	s.RegisterService(&_Auth_serviceDesc, srv)
}

func _Auth_CreateToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTokenReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).CreateToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth/CreateToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).CreateToken(ctx, req.(*CreateTokenReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_VerifyToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyTokenReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).VerifyToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth/VerifyToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).VerifyToken(ctx, req.(*VerifyTokenReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _Auth_serviceDesc = grpc.ServiceDesc{
	ServiceName: "auth",
	HandlerType: (*AuthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "create_token",
			Handler:    _Auth_CreateToken_Handler,
		},
		{
			MethodName: "verify_token",
			Handler:    _Auth_VerifyToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/proto/proto.proto",
}

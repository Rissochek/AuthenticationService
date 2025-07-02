package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"AuthService/internal/model"
	pb "Proto"
)

var ()

type (
	Database interface {
		InitDatabase() *gorm.DB
		SearchGUID(guid string) error
	}

	AuthManager interface {
		GenerateToken(user *model.User) (string, error)
		VerifyToken(user_token string) (*model.TokenClaims, error)
	}

	RefreshManager interface {
		GenerateRefreshToken() (string, error)
	}

	server struct {
		pb.UnimplementedAuthServer
		MainDB         Database
		AuthManager    AuthManager
		RefreshManager RefreshManager
	}
)

func NewServer(main_db Database) *server {
	return &server{MainDB: main_db}
}

func (s *server) GetTokens(ctx context.Context, user_request *pb.GetTokensMsg) (*pb.GetTokensReply, error) {
	if err := s.MainDB.SearchGUID(user_request.GUID); err != nil {
		return nil, status.Error(codes.NotFound, "GUID not found")
	}

	access, err := s.AuthManager.GenerateToken(&model.User{GUID: user_request.GUID})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate access token")
	}

	refresh, err := s.RefreshManager.GenerateRefreshToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate refresh token")
	}

	return &pb.GetTokensReply{Access: access, Refresh: refresh}, nil

}

func (s *server) RefreshTokens(ctx context.Context, user_request *pb.RefreshTokensMsg) (*pb.RefreshTokensReply, error) {
	return nil, nil
}

func (s *server) GetGUID(ctx context.Context, user_request *pb.GetGUIDMsg) (*pb.GetGUIDReply, error) {
	claims, err := s.AuthManager.VerifyToken(user_request.Access)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	
	return &pb.GetGUIDReply{Guid: claims.GUID}, nil 
}

func (s *server) Logout(ctx context.Context, user_request *pb.LogoutMsg) (*emptypb.Empty, error) {

	return nil, nil
}

package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
	log "github.com/sirupsen/logrus"

	"AuthService/internal/auth"
	"AuthService/internal/model"

	pb "Proto"
)

var ()

type (
	Database interface {
		InitDatabase() *gorm.DB
		SearchGUID(guid string) error
		DeleteSession(guid string) error
	}

	AuthManager interface {
		GenerateToken(user *model.User) (string, error)
		VerifyToken(user_token string) (auth.TokenClaims, error)
	}

	RefreshManager interface {
		GenerateRefreshToken() (string, error)
	}

	BlacklistManager interface {
		AddToBlacklist(token string, expiry int64, ctx context.Context) error
		BlacklistCkeck(ctx context.Context, token string) error
	}

	server struct {
		pb.UnimplementedAuthServer
		MainDB         Database
		AuthManager    AuthManager
		RefreshManager RefreshManager
		BlacklistManager BlacklistManager
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
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	token := md.Get("authorization")[0]
	if err := s.BlacklistManager.BlacklistCkeck(ctx, token); err != nil {
		log.Errorf("token is blacklisted: %v", err)
		return nil, status.Error(codes.Unauthenticated, "token is invalid")
	}
	
	claims, err := s.AuthManager.VerifyToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	
	return &pb.GetGUIDReply{Guid: claims.GUID}, nil 
}

func (s *server) Logout(ctx context.Context, user_request *pb.LogoutMsg) (*emptypb.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	token := md.Get("authorization")[0]
	claims, err := s.AuthManager.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	
	if err := s.BlacklistManager.AddToBlacklist(token, claims.ExpiresAt, ctx); err != nil {
		return nil, status.Error(codes.Internal, "failed to add token to blacklist")
	}

	if err := s.MainDB.DeleteSession(claims.GUID); err != nil {
		return nil, status.Error(codes.Internal, "failed to delete session")
	}
	return &emptypb.Empty{}, nil
}

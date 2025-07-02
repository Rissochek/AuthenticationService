package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"AuthService/internal/auth"
	"AuthService/internal/model"
	"AuthService/internal/utils"

	pb "Proto"
)

var ()

type (
	RefreshManager interface {
		GenerateRefreshToken() (string, error)
		GetExparationTime() (time.Duration)
	}

	Database interface {
		SearchGUID(guid string) error
		SearchSession(guid string, session_id uint) (*model.Session, error)
		DeleteSession(guid string, session_id uint) error
		AddSession(guid string, refresh_generator RefreshManager, user_agent string, user_ip string) (uint, string, error)
	}

	AuthManager interface {
		GenerateToken(user *model.User, session_id uint) (string, error)
		VerifyToken(user_token string, exparation_check bool) (auth.TokenClaims, error)
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

	user_agent, err := utils.GetFromMetadata(ctx, "user-agent")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user-agent header not provided")
	}

	user_ip, err := utils.GetFromMetadata(ctx, "x-forwarded-for")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "x-forwarder-for header not provided")
	}

	session_id, refresh, err := s.MainDB.AddSession(user_request.GUID, s.RefreshManager, user_agent, user_ip)
	if err != nil{
		return nil, status.Error(codes.Internal, "failed to add session in db")
	}

	access, err := s.AuthManager.GenerateToken(&model.User{GUID: user_request.GUID}, session_id)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate access token")
	}

	return &pb.GetTokensReply{Access: access, Refresh: refresh}, nil

}

func (s *server) RefreshTokens(ctx context.Context, user_request *pb.RefreshTokensMsg) (*pb.RefreshTokensReply, error) {
	//checking process
	access, err := utils.GetFromMetadata(ctx, "authorization")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "cant find authorization header")
	}

	user_agent, err := utils.GetFromMetadata(ctx, "user-agent")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user-agent header not provided")
	}

	user_ip, err := utils.GetFromMetadata(ctx, "x-forwarded-for")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "x-forwarder-for header not provided")
	}
	
	if err := s.BlacklistManager.BlacklistCkeck(ctx, access); err != nil {
		log.Errorf("token is blacklisted: %v", err)
		return nil, status.Error(codes.Unauthenticated, "token is invalid")
	}

	claims, err := s.AuthManager.VerifyToken(access, false)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	user_guid := claims.GUID
	if err := s.MainDB.SearchGUID(user_guid); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Guid not found")
	}

	session, err := s.MainDB.SearchSession(user_guid, claims.SessionId)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "cannot find session")
	}

	if session.UserAgent != user_agent {
		if err := s.BlacklistManager.AddToBlacklist(access, claims.ExpiresAt, ctx); err != nil {
			return nil, status.Error(codes.Internal, "failed to add token to blacklist")
		}
	
		if err := s.MainDB.DeleteSession(claims.GUID, claims.SessionId); err != nil {
			return nil, status.Error(codes.Internal, "failed to delete session")
		}
		
		return nil, status.Error(codes.Unauthenticated, "user-agent changed, session deauthorized")
	}

	if session.UserIP != user_ip {
		data := map[string] string {
			"message": "somebody wanted to refresh from another IP",
			"new_ip": user_ip,
			"old_ip": session.UserIP,
			"guid": user_guid,
			"sessionId": strconv.Itoa(int(session.ID)),
		}

		webhook := utils.GetKeyFromEnv("WEBHOOK_URL")
		json_data, err := json.Marshal(data)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed marshal data")
		}

		response, err := http.Post(webhook, "application/json", bytes.NewBuffer(json_data))
		if err != nil {
			return nil, status.Error(codes.Internal, "failed send to webhook")
		}
		response.Body.Close()
	}
	err = utils.CompareHashAndPassword(user_request.Refresh, session.Refresh)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "refresh token is invalid")
	}
	//generating process
	err = s.MainDB.DeleteSession(session.UserGUID, session.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to delete session")
	}

	err = s.BlacklistManager.AddToBlacklist(access, claims.ExpiresAt, ctx)
	if err != nil{
		return nil, status.Error(codes.Internal, "failed to add token to blacklist")
	}

	session_id, new_refresh, err := s.MainDB.AddSession(claims.GUID, s.RefreshManager, user_agent, user_ip)
	if err != nil{
		return nil, status.Error(codes.Internal, "failed to add session in db")
	}

	new_access, err := s.AuthManager.GenerateToken(&model.User{GUID: claims.GUID}, session_id)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate access token")
	}

	return &pb.RefreshTokensReply{Access: new_access, Refresh: new_refresh}, nil
}

func (s *server) GetGUID(ctx context.Context, _ *emptypb.Empty) (*pb.GetGUIDReply, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	token := md.Get("authorization")[0]
	if err := s.BlacklistManager.BlacklistCkeck(ctx, token); err != nil {
		log.Errorf("token is blacklisted: %v", err)
		return nil, status.Error(codes.Unauthenticated, "token is invalid")
	}

	claims, err := s.AuthManager.VerifyToken(token, true)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	
	return &pb.GetGUIDReply{Guid: claims.GUID}, nil 
}

func (s *server) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	token := md.Get("authorization")[0]
	claims, err := s.AuthManager.VerifyToken(token, true)
	if err != nil {
		return nil, err
	}
	
	if err := s.BlacklistManager.AddToBlacklist(token, claims.ExpiresAt, ctx); err != nil {
		return nil, status.Error(codes.Internal, "failed to add token to blacklist")
	}

	if err := s.MainDB.DeleteSession(claims.GUID, claims.SessionId); err != nil {
		return nil, status.Error(codes.Internal, "failed to delete session")
	}
	return &emptypb.Empty{}, nil
}

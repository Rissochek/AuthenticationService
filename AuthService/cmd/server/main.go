package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"AuthService/internal/auth"
	"AuthService/internal/database"
	"AuthService/internal/model"
	"AuthService/source/utils"

	pb "Proto"
)

type (
	server struct {
		pb.UnimplementedAuthServer
		MainDB           database.Database
		AuthManager      auth.AuthManager
		RefreshManager   auth.RefreshManager
		BlacklistManager database.BlacklistManager
	}
)

func NewServer(main_db database.Database, auth_manager auth.AuthManager, refresh_manager auth.RefreshManager, blacklist_manager database.BlacklistManager) *server {
	return &server{MainDB: main_db, AuthManager: auth_manager, RefreshManager: refresh_manager, BlacklistManager: blacklist_manager}
}

func (s *server) GetTokens(ctx context.Context, user_request *pb.GetTokensMsg) (*pb.GetTokensReply, error) {
	if err := s.MainDB.SearchGUID(user_request.Guid); err != nil {
		return nil, status.Error(codes.NotFound, "GUID not found")
	}

	user_agent, err := utils.GetFromMetadata(ctx, "x-user-agent")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user-agent header not provided")
	}

	user_ip, err := utils.GetFromMetadata(ctx, "x-forwarded-for")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "x-forwarder-for header not provided")
	}

	session_id, refresh, err := s.MainDB.AddSession(user_request.Guid, s.RefreshManager, user_agent, user_ip)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to add session in db")
	}

	access, err := s.AuthManager.GenerateToken(&model.User{GUID: user_request.Guid}, session_id)
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

	user_agent, err := utils.GetFromMetadata(ctx, "x-user-agent")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user-agent header not provided")
	}

	user_ip, err := utils.GetFromMetadata(ctx, "x-forwarded-for")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "x-forwarder-for header not provided")
	}

	is_blacklisted, err := s.BlacklistManager.BlacklistCheck(ctx, access)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed blacklist check")
	}
	if is_blacklisted {
		return nil, status.Error(codes.Unauthenticated, "token is blacklisted")
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
		token, err := auth.ExtractToken(access)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if err := s.BlacklistManager.AddToBlacklist(token, claims.ExpiresAt, ctx); err != nil {
			return nil, status.Error(codes.Internal, "failed to add token to blacklist")
		}

		if err := s.MainDB.DeleteSession(claims.GUID, claims.SessionId); err != nil {
			return nil, status.Error(codes.Internal, "failed to delete session")
		}

		return nil, status.Error(codes.Unauthenticated, "user-agent changed, session deauthorized")
	}

	if session.UserIP != user_ip {
		data := map[string]string{
			"message":   "somebody wanted to refresh from another IP",
			"new_ip":    user_ip,
			"old_ip":    session.UserIP,
			"guid":      user_guid,
			"sessionId": strconv.Itoa(int(session.ID)),
		}

		webhook := utils.GetKeyFromEnv("WEBHOOK_URL")
		json_data, err := json.Marshal(data)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed marshal data")
		}

		response, err := http.Post(webhook, "application/json", bytes.NewBuffer(json_data))
		if err != nil {
			log.Errorf("failed to send to webhook: %v", err)
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

	token, err := auth.ExtractToken(access)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	err = s.BlacklistManager.AddToBlacklist(token, claims.ExpiresAt, ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to add token to blacklist")
	}

	session_id, new_refresh, err := s.MainDB.AddSession(claims.GUID, s.RefreshManager, user_agent, user_ip)
	if err != nil {
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

	raw_token := md.Get("authorization")
	if raw_token == nil {
		return nil, status.Error(codes.Unauthenticated, "authorization header is not provided")
	}

	token := raw_token[0]
	is_blacklisted, err := s.BlacklistManager.BlacklistCheck(ctx, token)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed blacklist check")
	}
	if is_blacklisted {
		return nil, status.Error(codes.Unauthenticated, "token is blacklisted")
	}

	claims, err := s.AuthManager.VerifyToken(token, true)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.GetGUIDReply{Guid: claims.GUID}, nil
}

func (s *server) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	token, err := utils.GetFromMetadata(ctx, "authorization")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "cant find authorization header")
	}

	claims, err := s.AuthManager.VerifyToken(token, true)
	if err != nil {
		return nil, err
	}

	token, err = auth.ExtractToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.BlacklistManager.AddToBlacklist(token, claims.ExpiresAt, ctx); err != nil {
		return nil, status.Error(codes.Internal, "failed to add token to blacklist")
	}

	if err := s.MainDB.DeleteSession(claims.GUID, claims.SessionId); err != nil {
		return nil, status.Error(codes.Internal, "failed to delete session")
	}
	return &emptypb.Empty{}, nil
}

func (s *server) AddUser(context.Context, *emptypb.Empty) (*pb.AddUserReply, error) {
	guid, err := s.MainDB.AddUser()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to add user to database")
	}
	return &pb.AddUserReply{Guid: guid}, nil
}

func main() {
	utils.LoadEnvFile()
	port, _ := strconv.Atoi(utils.GetKeyFromEnv("AUTH_HOST_PORT"))
	access_life_time, _ := strconv.Atoi(utils.GetKeyFromEnv("ACCESS_LIFE_TIME"))
	resresh_life_time, _ := strconv.Atoi(utils.GetKeyFromEnv("REFRESH_LIFE_TIME"))
	refresh_length, _ := strconv.Atoi(utils.GetKeyFromEnv("REFRESH_LENGTH"))
	
	db := database.InitDataBase()
	main_db := database.NewPostgresDB(db)
	auth_manager := auth.NewJWTManager(time.Duration(access_life_time) * time.Minute)
	refresh_manager := auth.NewRefreshGenerator(int64(refresh_length), (time.Duration(resresh_life_time)*time.Hour))
	blacklist_manager := database.NewRedisManager()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen %v", err)
	}

	var opts []grpc.ServerOption
	if err != nil {
		log.Fatalf("failed to initialize interceptor: %v", err)
	}

	server := NewServer(main_db, auth_manager, refresh_manager, blacklist_manager)
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthServer(grpcServer, server)
	log.Printf("Server listening on: %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import LoginSerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

User = get_user_model()

class RegisterApiView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
            operation_summary="Register a new user",
            operation_description=" **POST /api/accounts/register/** Create a new user account with email, username, password, departments, level.",
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "email": openapi.Schema(type=openapi.TYPE_STRING, example="testuser@yct.edu.ng"),
                    "username": openapi.Schema(type=openapi.TYPE_STRING, example="testuser"),
                    "role": openapi.Schema(type=openapi.TYPE_STRING, example="student"),
                    "department": openapi.Schema(type=openapi.TYPE_STRING, example="Computer Engineering"),
                    "level": openapi.Schema(type=openapi.TYPE_STRING, example="ND1"),
                    "password1": openapi.Schema(type=openapi.TYPE_STRING, example="StrongPass123!"),
                    "password2": openapi.Schema(type=openapi.TYPE_STRING, example="StrongPass123!")
                },
                required=['email', 'username', 'password1', 'password2', 'department', 'role', 'level']
            ),
            responses={
                201: UserSerializer,
                400: 'Bad Request'
            }
    )
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh_token = RefreshToken.for_user(user)
            
            return Response({
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username
                },
                'tokens': {
                    'refresh': str(refresh_token),
                    'access': str(refresh_token.access_token),
                }
            }, status=status.HTTP_201_CREATED)

        return Response(
            {'errors': serializer.errors}, 
            status=status.HTTP_400_BAD_REQUEST
        )

class LoginApiView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
            operation_summary="User Login",
            operation_description=" **POST** `/api/accounts/login/` - Authenticate user with email and password.",
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "email": openapi.Schema(type=openapi.TYPE_STRING, example="testuser@yct.edu.ng"),
                    "password": openapi.Schema(type=openapi.TYPE_STRING, example="StrongPass123!")
                },
                required=["email", "password"]
            ),
            responses={
                200: 'Login successful',
                400: 'Bad Request',
                401: 'Unauthorized',
                403: 'Forbidden'
            }
    )

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'errors': serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data['email'].lower().strip()
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)

        if not user:
            return Response(
                {'error': 'Invalid email or password'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        if not user.is_active:
            return Response(
                {'error': 'Account inactive. Please contact support.'}, 
                status=status.HTTP_403_FORBIDDEN
            )

        refresh = RefreshToken.for_user(user)

        return Response({
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username
            },
            'tokens': {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            }
        }, status=status.HTTP_200_OK)

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
            operation_summary="Protected View",
            operation_description=" **GET** `/api/accounts/protected/` A view that requires authentication.",
            responses={
                200: 'Success',
                401: 'Unauthorized'
            }
    )
    def get(self, request):
        user = request.user
        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'message': 'This is a protected view'
        })




class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
            operation_summary="Logout User",
            operation_description=" **POST** `/api/accounts/logout/` - Invalidate the user's refresh token.",
            request_body=None,
            responses={
                205: 'Logout successful',
                400: 'Bad Request',
                401: 'Unauthorized'
            }
    )
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    @swagger_auto_schema(
        operation_summary="Token Login (JWT)",
        operation_description="**POST** `/api/token/` — Login with email and password to get access & refresh tokens.",
        tags=["Auth"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "password"],
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING, example="testuser@yct.edu.ng"),
                "password": openapi.Schema(type=openapi.TYPE_STRING, example="StrongPass123!")
            },
        ),
        responses={
            200: openapi.Response(
                description="JWT Token Pair",
                examples={
                    "application/json": {
                        "refresh": "refresh_token_here",
                        "access": "access_token_here"
                    }
                }
            ),
            401: "Invalid credentials"
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class CustomTokenRefreshView(TokenRefreshView):
    @swagger_auto_schema(
        operation_summary="Refresh JWT token",
        operation_description="**POST** `/api/token/refresh/` — Use refresh token to get new access token.",
        tags=["Auth"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["refresh"],
            properties={
                "refresh": openapi.Schema(type=openapi.TYPE_STRING, example="your_refresh_token_here"),
            }
        ),
        responses={
            200: openapi.Response(
                description="New access token",
                examples={
                    "application/json": {
                        "access": "new_access_token_here"
                    }
                }
            ),
            401: "Invalid or expired refresh token"
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

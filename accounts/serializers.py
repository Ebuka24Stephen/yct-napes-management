from rest_framework import serializers 
from .models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.core.validators import validate_email
class UserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User 
        fields = ['email', 'username', 'role', 'department', 'level', 'password1', 'password2']

    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError('Passwords do not match')
        validate_password(attrs['password1'])
        return attrs

    def validate_email(self, value):
        value = value.lower().strip()
        try:
            validate_email(value)
        except serializers.ValidationError:
            raise serializers.ValidationError('Enter a valid email address')
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already  exists')
        return value

    def validate_username(self, value):
        value = value.strip()
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def create(self, validated_data):
        validated_data.pop('password2') 
        password = validated_data.pop('password1')

        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role=validated_data['role'],
            department=validated_data['department'],
            level=validated_data['level'],  
        )
        user.set_password(password)
        user.save()
        return user


# Login Serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid credentials")

        attrs['user'] = user
        return attrs

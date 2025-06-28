from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny


class HomeView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({'Ogbeni no w!': 'Welcome to the API!'}, status=status.HTTP_200_OK)
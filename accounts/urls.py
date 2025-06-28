from .views import LoginApiView, RegisterApiView, ProtectedView, LogoutView
from django.urls import path 

urlpatterns = [
    path('register/', RegisterApiView.as_view()),
    path('login/', LoginApiView.as_view()),
    path('protected/', ProtectedView.as_view()),
    path('logout/', LogoutView.as_view(), name='logout'),

]
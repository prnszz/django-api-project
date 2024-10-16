# api/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('signup', views.signup, name='signup'),
    path('users/<str:user_id>/', views.user_detail, name='user_detail'),
    path('users/<str:user_id>', views.user_detail, name='user_detail'),
    path('close/', views.close_account, name='close_account'),
    path('close', views.close_account, name='close_account'),
    path('test/', views.test_view, name='test_view'),
    path('connection', views.test_db, name='test_db'),
]
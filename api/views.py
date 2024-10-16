#api/views.py
import logging
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from django.db import IntegrityError
from django.conf import settings
from django.http import JsonResponse
from django.db import connection
from .models import User
from .serializers import UserSerializer
import re

logger = logging.getLogger(__name__)

@api_view(['POST'])
def signup(request):
    try:
        user_id = request.data.get('user_id')
        password = request.data.get('password')

        if not user_id or not password:
            return Response({"message": "Account creation failed", "cause": "required user_id and password"}, status=status.HTTP_400_BAD_REQUEST)

        if not isinstance(user_id, str) or not isinstance(password, str):
            return Response({"message": "Account creation failed", "cause": "user_id and password must be strings"}, status=status.HTTP_400_BAD_REQUEST)

        if not (6 <= len(user_id) <= 20) or not re.match(r'^[a-zA-Z0-9]+$', user_id):
            return Response({"message": "Account creation failed", "cause": "user_id should be 6-20 alphanumeric characters"}, status=status.HTTP_400_BAD_REQUEST)

        if not (8 <= len(password) <= 20) or not re.match(r'^[\x21-\x7E]+$', password):
            return Response({"message": "Account creation failed", "cause": "password should be 8-20 printable ASCII characters"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(user_id=user_id).exists():
            return Response({"message": "Account creation failed", "cause": "already same user_id is used"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(user_id=user_id, password=password)
        return Response({
            "message": "Account successfully created",
            "user": {
                "user_id": user.user_id,
                "nickname": user.nickname or user.user_id
            }
        }, status=status.HTTP_200_OK)
    except IntegrityError as e:
        logger.error(f"IntegrityError in signup: {str(e)}")
        return Response({"message": "Account creation failed", "cause": "Database integrity error"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Unexpected error in signup: {str(e)}", exc_info=True)
        return Response({"message": "Account creation failed", "cause": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'PATCH'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def user_detail(request, user_id):

    if not request.user.is_authenticated:
        return Response({"message": "Authentication Failed"}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return Response({
            "message": "User details by user_id",
            "user": {
                "user_id": user.user_id,
                "nickname": user.nickname or user.user_id,
                "comment": user.comment
            }
        }, status=status.HTTP_200_OK)

    elif request.method == 'PATCH':
        if request.user.user_id != user_id:
            return Response({"message": "No Permission for Update"}, status=status.HTTP_403_FORBIDDEN)

        nickname = request.data.get('nickname')
        comment = request.data.get('comment')
        if nickname is None:
            nickname = user.user_id

        if 'user_id' in request.data or 'password' in request.data:
            return Response({"message": "User updation failed", "cause": "not updatable user_id and password"}, status=status.HTTP_400_BAD_REQUEST)

        if nickname is None and comment is None:
            return Response({"message": "User updation failed", "cause": "required nickname or comment"}, status=status.HTTP_400_BAD_REQUEST)

        if nickname is not None:
            if not isinstance(nickname, str) or len(nickname) > 30:
                return Response({"message": "User updation failed", "cause": "nickname should be a string with less than 30 characters"}, status=status.HTTP_400_BAD_REQUEST)
            user.nickname = nickname if nickname else user.user_id

        if comment is not None:
            if not isinstance(comment, str) or len(comment) > 100:
                return Response({"message": "User updation failed", "cause": "comment should be a string with less than 100 characters"}, status=status.HTTP_400_BAD_REQUEST)
            user.comment = comment

        else:
            return Response({"message": "User updation failed"}, status=status.HTTP_401_UNAUTHORIZED)

        user.save()
        return Response({
            "message": "User successfully updated",
            "user": {
                "nickname": user.nickname,
                "comment": user.comment
            }
        }, status=status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def close_account(request):
    if not request.user.is_authenticated:
        return Response({"message": "Authentication Failed"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        user = request.user
        if user.is_authenticated:
            user.delete()
            return Response({"message": "Account and user successfully removed"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Authentication Failed"}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        logger.error(f"Unexpected error in close_account: {str(e)}", exc_info=True)
        return Response({"message": "Account deletion failed", "cause": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # return Response({"message": "Account deletion failed"}, status=status.HTTP_401_UNAUTHORIZED)

def test_view(request):
    return JsonResponse({"message": "API is working"})




def test_db(request):
    response = {
        "status": "Checking database connection",
        "database_config": str(settings.DATABASES['default']),
        "error": None
    }
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
        response["status"] = "Database connection successful"
        response["result"] = row[0]
    except Exception as e:
        response["status"] = "Database connection failed"
        response["error"] = str(e)
    return JsonResponse(response)
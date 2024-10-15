from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import User
from .serializers import UserSerializer
import re

@api_view(['POST'])
def signup(request):
    user_id = request.data.get('user_id')
    password = request.data.get('password')

    if not user_id or not password:
        return Response({"message": "Account creation failed", "cause": "required user_id and password"}, status=status.HTTP_400_BAD_REQUEST)

    if not (6 <= len(user_id) <= 20) or not re.match(r'^[a-zA-Z0-9]+$', user_id):
        return Response({"message": "Account creation failed", "cause": "user_id should be 6-20 alphanumeric characters"}, status=status.HTTP_400_BAD_REQUEST)

    if not (8 <= len(password) <= 20) or not re.match(r'^[\x21-\x7E]+$', password):
        return Response({"message": "Account creation failed", "cause": "password should be 8-20 printable ASCII characters"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(user_id=user_id).exists():
        return Response({"message": "Account creation failed", "cause": "already same user_id is used"}, status=status.HTTP_400_BAD_REQUEST)

    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.set_password(password)
        user.save()
        return Response({
            "message": "Account successfully created",
            "user": {
                "user_id": user.user_id,
                "nickname": user.nickname or user.user_id
            }
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PATCH'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def user_detail(request, user_id):
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response({
            "message": "User details by user_id",
            "user": serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'PATCH':
        if request.user.user_id != user_id:
            return Response({"message": "No Permission for Update"}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "User successfully updated",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def close_account(request):
    user = request.user
    user.delete()
    return Response({"message": "Account and user successfully removed"}, status=status.HTTP_200_OK)
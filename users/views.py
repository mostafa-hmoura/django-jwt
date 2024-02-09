from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializiers import UserSerializer
from .models import User
from rest_framework.exceptions import AuthenticationFailed

import jwt
import datetime


class RegisterView(APIView):
    def post(self, request):
        serializier = UserSerializer(data=request.data)
        serializier.is_valid(raise_exception=True)
        serializier.save()
        return Response(serializier.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User Not Found !')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect Password !')

        payload = {
            'id': user.id,
            'email': user.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'sbtx', algorithm='HS256')
        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'token': token
        }

        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'sbtx', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()
        user = UserSerializer(user)

        return Response(user.data)


class LogoutView(APIView):
    def post(self, request):
        res = Response()
        res.delete_cookie('jwt')
        res.data = {
            'message': 'success'
        }
        return res

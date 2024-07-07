from django.db.models import Q
from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView, ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from app.models import User, Organisation
from app.serializers import CreateUserSerializer, CTokenObtainPairSerializer, GetUserRecordSerializer, \
    OrganisationListCreateSerializer, AddUserToOrganisationSerializer


# Create your views here.

class CreateUserAPIView(CreateAPIView):
    serializer_class = CreateUserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data)

        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            response_data = {'status': 'success',
                             'message': 'Registration successful',
                             'data': {'accessToken': str(refresh.access_token),
                                      'user': {'userId': user.userId,
                                               'firstName': user.firstName,
                                               'lastName': user.lastName,
                                               'email': user.email,
                                               'phone': user.phone}}}
            return Response(data=response_data, status=status.HTTP_201_CREATED)
        else:
            response_error = {'status': 'Bad request',
                              'message': 'Registration unsuccessful',
                              'statusCode': status.HTTP_400_BAD_REQUEST,
                              'errors': serializer.errors}
            return Response(data=response_error, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class LoginAPIView(TokenObtainPairView):
    serializer_class = CTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.user or request.user
            print(user)

            request.user = user
            response_data = {'status': 'success',
                             'message': 'Login successful',
                             'data': {'accessToken': serializer.validated_data.get('access'),
                                      'user': {'userId': user.userId,
                                               'firstName': user.firstName,
                                               'lastName': user.lastName,
                                               'email': user.email,
                                               'phone': user.phone}}}

            return Response(data=response_data, status=status.HTTP_200_OK)

        response_error = {'status': 'Bad request',
                          'message': 'Authentication failed',
                          'statusCode': status.HTTP_401_UNAUTHORIZED,
                          'errors': serializer.errors}

        return Response(data=response_error, status=status.HTTP_401_UNAUTHORIZED)


class GetUserRecordAPIView(RetrieveAPIView):
    serializer_class = GetUserRecordSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        userId = kwargs.get('userId')
        user = self.get_user_record(userId, request.user)

        if user is None:
            response_data = {
                'status': 'error',
                'message': 'User not found or access denied'
            }
            return Response(data=response_data, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(user)
        data = serializer.data

        response_data = {
            'status': 'success',
            'message': 'Retrieved successfully',
            'data': data
        }
        return Response(data=response_data, status=status.HTTP_200_OK)

    def get_user_record(self, userId, current_user):
        try:
            if userId == current_user.userId or userId in current_user.organisations.values_list('member__userId',
                                                                                                 flat=True):
                return User.objects.get(userId=userId)
            if Organisation.objects.filter(createdBy=current_user, member__userId=userId).exists():
                return User.objects.get(userId=userId)
        except User.DoesNotExist:
            return None


class OrganisationListCreateAPIView(ListCreateAPIView):
    serializer_class = OrganisationListCreateSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = Organisation.objects.filter(Q(member=self.request.user) | Q(createdBy=self.request.user))
        return queryset

    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)

        response_data = {
            'status': 'success',
            'message': 'Retrieved successfully',
            'data': {
                'organisations': serializer.data
            }
        }
        return Response(data=response_data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data)

        if serializer.is_valid():
            obj = serializer.save()

            obj.createdBy = self.request.user
            obj.save()

            response_data = {'status': 'success',
                             'message': 'Organisation created successfully',
                             'data': {'orgId': obj.orgId,
                                      'name': obj.name,
                                      'description': obj.description
                                      }}
            return Response(data=response_data, status=status.HTTP_201_CREATED)

        else:
            response_error = {'status': 'Bad request',
                              'message': 'Client error',
                              'statusCode': status.HTTP_400_BAD_REQUEST,
                              'errors': serializer.errors}
            return Response(data=response_error, status=status.HTTP_400_BAD_REQUEST)


class GetOrganisationRecordAPIView(RetrieveAPIView):
    serializer_class = OrganisationListCreateSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        orgId = kwargs.get('orgId')
        org = self.get_org_record(orgId)

        if org is None:
            response_data = {
                'status': 'error',
                'message': 'User not found or access denied'
            }
            return Response(data=response_data, status=status.HTTP_404_NOT_FOUND)

        if org and org.createdBy != self.request.user and self.request.user not in org.member.all():
            response_data = {
                'status': 'error',
                'message': 'Access denied'
            }
            return Response(data=response_data, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(org)
        data = serializer.data

        response_data = {
            'status': 'success',
            'message': 'Retrieved successfully',
            'data': data
        }
        return Response(data=response_data, status=status.HTTP_200_OK)

    def get_org_record(self, orgId):
        try:
            return Organisation.objects.get(orgId=orgId)
        except Organisation.DoesNotExist:
            return None


class AddUserToOrganisationAPIView(CreateAPIView):
    serializer_class = AddUserToOrganisationSerializer

    def post(self, request, *args, **kwargs):
        orgId = kwargs.get('orgId')
        serializer = self.get_serializer(data=self.request.data)

        try:
            org = Organisation.objects.get(orgId=orgId)
        except Organisation.DoesNotExist:
            response_error = {'status': 'Bad request',
                              'message': 'Client error',
                              'statusCode': status.HTTP_400_BAD_REQUEST,
                              'errors': 'Organisation does not exist.'}
            return Response(data=response_error, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            userId = serializer.validated_data.get('userId')

            try:
                user = User.objects.get(userId=userId)
            except User.DoesNotExist:
                response_error = {'status': 'Bad request',
                                  'message': 'Client error',
                                  'statusCode': status.HTTP_400_BAD_REQUEST,
                                  'errors': 'User does not exist.'}
                return Response(data=response_error, status=status.HTTP_400_BAD_REQUEST)

            org.member.add(user)

            return Response(data={'status': 'success', 'message': 'User added to organisation successfully'},
                            status=status.HTTP_200_OK)
        else:
            response_error = {'status': 'Bad request',
                              'message': 'Client error',
                              'statusCode': status.HTTP_400_BAD_REQUEST,
                              'errors': serializer.errors}
            return Response(data=response_error, status=status.HTTP_400_BAD_REQUEST)

from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from app.models import User, Organisation
from app.utils import EmailAuthenticate

email_authenticate = EmailAuthenticate()


class CreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('userId', 'firstName', 'lastName', 'email', 'phone', 'password')
        extra_kwargs = {
            "userId": {"read_only": True},
        }

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('User with email already exist!')

        return attrs

    def create(self, validated_data):
        first_name = validated_data.get('firstName')
        user = User.objects.create_user(**validated_data)
        name = f"{first_name}'s Organisation"
        organisation = Organisation.objects.create(name=name, createdBy=user)
        organisation.member.add(user)
        return user


class CTokenObtainPairSerializer(TokenObtainSerializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    token_class = RefreshToken

    def validate(self, attrs):

        authenticate_kwargs = {'email': attrs['email'], "password": attrs["password"], }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        try:
            self.user = email_authenticate.authenticate(**authenticate_kwargs)
        except User.MultipleObjectsReturned:
            raise serializers.ValidationError("Access denied due to mistaken identity", "no_user_found")
        except Exception as e:
            raise serializers.ValidationError(f"Login error: {str(e)}", "no_user_found")

        if self.user is None:
            raise serializers.ValidationError("Access denied due to invalid credentials", "no_user_found")

        if not self.user.is_active:
            raise serializers.ValidationError("User is not active", "in_active")

        data = {}

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        update_last_login(None, self.user)

        return data


class GetUserRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('userId', 'firstName', 'lastName', 'email', 'phone')


class OrganisationListCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ('orgId', 'name', 'description')
        extra_kwargs = {
            "orgId": {"read_only": True},
        }


class AddUserToOrganisationSerializer(serializers.Serializer):
    userId = serializers.CharField()

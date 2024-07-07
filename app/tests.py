import datetime
import time
import uuid

import jwt
from django.conf import settings
from django.test import TestCase

# Create your tests here.
from django.urls import reverse
from django.contrib.auth.models import Permission

from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from app.models import User, Organisation


class UserTestCase(APITestCase):

    def create_user(self, firstName, lastName, email, password):
        url = reverse('user-register')
        data = {
            'firstName': firstName,
            'lastName': lastName,
            'email': email,
            'password': password,
        }
        return self.client.post(url, data, format='json')

    def login_user(self, email, password):
        url = reverse('login-user')
        data = {
            'email': email,
            'password': password,
        }
        return self.client.post(url, data, format='json')

    def get_organisation(self, name):
        try:
            return Organisation.objects.get(name=name)
        except Organisation.DoesNotExist:
            return None

    def get_token_payload(self, token):
        try:
            return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.InvalidSignatureError:
            print("Token:", token)
            print("SECRET_KEY:", settings.SECRET_KEY)
            raise


class UserRegistrationTests(UserTestCase):

    def test_register_user_with_default_org(self):
        response = self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        org = self.get_organisation("John's Organisation")
        self.assertIsNotNone(org, "Organisation was not created")
        self.assertEqual(org.name, "John's Organisation")
        self.assertIn('accessToken', response.data.get('data'))
        self.assertIn('user', response.data.get('data'))
        self.assertEqual(response.data.get('data')['user']['email'], 'john.doe@example.com')


class UserLoginTests(UserTestCase):

    def setUp(self):
        self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')

    def test_login_user_success(self):
        response = self.login_user('john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('accessToken', response.data.get('data'))
        self.assertIn('user', response.data.get('data'))
        self.assertEqual(response.data.get('data')['user']['email'], 'john.doe@example.com')

    def test_login_user_failure(self):
        response = self.login_user('john.doe@example.com', 'wrongpassword')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('errors', response.data)


class UserRegistrationFieldValidationTests(UserTestCase):

    def test_missing_first_name(self):
        response = self.create_user('', 'Doe', 'john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('firstName', response.data.get('errors'))

    def test_missing_last_name(self):
        response = self.create_user('John', '', 'john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('lastName', response.data.get('errors'))

    def test_missing_email(self):
        response = self.create_user('John', 'Doe', '', 'password123')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data.get('errors'))

    def test_missing_password(self):
        response = self.create_user('John', 'Doe', 'john.doe@example.com', '')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data.get('errors'))


class UserRegistrationDuplicateTests(UserTestCase):

    def setUp(self):
        self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')

    def test_duplicate_email(self):
        response = self.create_user('Jane', 'Smith', 'john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data.get('errors'))

    def test_duplicate_user_id(self):
        response = self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data.get('errors'))


class TokenTests(UserTestCase):

    def test_token_contains_correct_user_details(self):
        self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')
        response = self.login_user('john.doe@example.com', 'password123')
        access_token = response.data.get('data')['accessToken']

        payload = self.get_token_payload(access_token)
        print('payload', payload)
        self.assertEqual(payload['user_id'], 'john.doe@example.com')
        self.assertIn('exp', payload)

    def test_token_expiration(self):
        self.create_user('John', 'Doe', 'john.doe@example.com', 'password123')
        response = self.login_user('john.doe@example.com', 'password123')
        access_token = response.data.get('data')['accessToken']

        payload = self.get_token_payload(access_token)
        expiration_time = payload['exp']
        current_time = time.time()

        self.assertGreater(expiration_time, current_time)
        # Check that token expires within expected time frame (e.g., 5 minutes)
        self.assertLess(expiration_time, current_time + 300)


class OrganisationAccessTests(UserTestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(firstName='John', lastName='Doe', email='john.doe@example.com',
                                              password='password123')
        self.user2 = User.objects.create_user(firstName='Jane', lastName='Smith', email='jane.smith@example.com',
                                              password='password123')

        self.org1 = Organisation.objects.create(name="John's Organisation", createdBy=self.user1)
        self.org2 = Organisation.objects.create(name="Jane's Organisation", createdBy=self.user2)

        self.org1.member.add(self.user1)
        self.org2.member.add(self.user2)

    def test_user_cannot_access_other_users_organisation(self):
        self.client.force_authenticate(user=self.user1)
        url = reverse('organisation-detail', kwargs={'orgId': self.org2.orgId})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_can_access_own_organisation(self):
        self.client.force_authenticate(user=self.user1)
        url = reverse('organisation-detail', kwargs={'orgId': self.org1.orgId})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

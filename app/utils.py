import re
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

User = get_user_model()


class EmailAuthenticate(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        user = None

        if is_valid_email(email):
            user = User.objects.filter(email=email).first()

        if user is None:
            user = User.objects.filter(username=email).first()

        if user and user.check_password(password):
            return user
        return None

    def get_user(self, user_id):
        return User.objects.filter(id=user_id).first()


def is_valid_email(email):
    # Define a regular expression pattern for matching email addresses
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+'
    return re.match(email_pattern, email) is not None

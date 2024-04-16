# Django Imports
from django.contrib.auth import get_user_model
from django.core.validators import EmailValidator
from django.contrib.auth.password_validation import validate_password
from django.conf import settings

# Rest Framework Imports
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch


User = get_user_model()


class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "email",
            "password"
        ]

        # Use this to define which variables are read only and write_only
        extra_kwargs = {
            "password": {"write_only": True},
            'email': {
                'validators': [EmailValidator]
            }
        }

    # Naming convention - validate_ followed by field name
    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_email(self, value):
        lower_case_email = value.lower()
        return lower_case_email

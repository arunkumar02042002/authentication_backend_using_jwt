# Django imports
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str

# Rest Framework Imports
from rest_framework.generics import GenericAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework import permissions as rest_permissions


# Current app Imports
from .serializers import CreateUserSerializer
from .helpers import AuthHelper, validation_error_handler
from .tokens import account_activation_token, password_reset_token


User = get_user_model()


class SignUpView(GenericAPIView):

    # DRF uses this variable to display the deafult html template
    serializer_class = CreateUserSerializer

    def post(self, request, *args, **kwargs):
        request_data = request.data
        # data is required - otherwise it will not perform validations
        serializer = self.serializer_class(data=request_data)

        if serializer.is_valid() is False:
            return Response({
                "status": "error",
                # For the toast
                "message": validation_error_handler(serializer.errors),
                "payload": {
                    "errors": serializer.errors
                }
            }, status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        email = validated_data['email']
        password = validated_data['password']

        existing_user = User.objects.filter(email=email).first()

        if existing_user is not None:
            # If verification fails because of third-party apps, user can signup again
            if existing_user.is_active is False:
                existing_user.set_password(password)
                existing_user.save()
                user = existing_user
            else:
                return Response({
                    "stautus": "error",
                    "message": "Account with this email address already exists.",
                    "payload": {},
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            username = AuthHelper.create_username(email=email)
            user = User.objects.create_user(
                username=username,
                is_active=False,
                **validated_data
            )

        serializer_data = self.serializer_class(user).data

        # Email
        # subject = "Verify Email for your Account Verification on WonderShop"
        # template = "auth/email/verify_email.html"
        # context_data = {
        #     "host": settings.FRONTEND_HOST,
        #     "uid": urlsafe_base64_encode(force_bytes(user.id)),
        #     "token": account_activation_token.make_token(user=user),
        #     "protocol": settings.FRONTEND_PROTOCOL
        # }

        print(
            f"uid: {urlsafe_base64_encode(force_bytes(user.id))}, token: {account_activation_token.make_token(user=user)}")
        try:
            # Send Verification Email here

            return Response({
                "status": "success",
                "message": "Sent the account verification link to your email address",
                "payload": {
                    **serializer_data,
                    # For log in purpose, If the email is the verified this token will not work.
                    "tokens": AuthHelper.get_tokens_for_user(user)
                }
            })
        except Exception:
            # logger.error(
            #     "Some error occurred in signup endpoint", exc_info=True)
            return Response({
                "status": "error",
                "message": "Some error occurred",
                "payload": {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ActivateAccountView(GenericAPIView):

    def get(self, request, *args, **kwargs):

        try:
            uidb64 = kwargs['uidb64']
            token = kwargs['token']
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()

            return Response({
                'status': 'success',
                'message': 'account verified',
                'payload': {},
            }, status=status.HTTP_200_OK)

        return Response({
            "status": "error",
            "message": "Activation link is invalid",
            "payload": {}
        }, status=status.HTTP_403_FORBIDDEN)

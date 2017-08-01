import logging

from django.conf import settings
from django.contrib.auth import login
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.template import loader
from django.utils.translation import ugettext_lazy as _
from project.apps.core.api.serializers import LoginSerializer
from project.apps.core.api.serializers import UserSerializer, UserRegistrationSerializer, ForgotPasswordSerializer
from project.apps.core.models import User
from project.utils.network import get_client_ip
from project.utils.permissions import IsNotAuthenticated
from rest_framework import generics
from rest_framework import mixins
# from django.contrib.auth import login, logout
# from django.conf import settings
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


class LoginView(GenericAPIView):
    permission_classes = (IsNotAuthenticated,)
    # permission_classes = ()
    serializer_class = LoginSerializer

    # def process_login(self):
    #     login(self.request, self.user)

    def get_response_serializer(self):
        return
        # return TokenSerializer

    def login(self):
        self.user = self.serializer.validated_data['user']
        self.token = self.create_token(self.user)

    def create_token(self, user):
        pass
        # # if settings.CAN_LOGIN_WITH_MULTIPLE_IP:
        # token, created = Token.objects.get_or_create(ip=get_client_ip(self.request), user=user,
        #                                              user_agent=get_user_agent(self.request))
        # if not created:
        #     token.key = token.generate_key()
        #     token.save()
        # return token

    def get_response(self):
        serializer_class = self.get_response_serializer()

        serializer = serializer_class(instance=self.token,
                                      context={'request': self.request})

        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        self.login()
        return self.get_response()


class LogoutView(APIView):
    def get(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        # logout(request)
        return Response({"detail": _("Successfully logged out.")},
                        status=status.HTTP_200_OK)


class UserRegistration(mixins.CreateModelMixin, generics.GenericAPIView):
    permission_classes = (IsNotAuthenticated,)
    # pagination_class = None
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class Profile(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, generics.GenericAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = UserSerializer

    def retrieve(self, request, pk=None):
        """
        If provided 'pk' is "me" then return the current user.
        """
        if request.user and not pk:
            return Response(UserSerializer(request.user).data)
        return super(Profile, self).retrieve(request, pk)

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)


class ForgotPassword(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = (IsNotAuthenticated,)

    template_name = 'password_reset/recovery_form.html'
    email_template_name = 'password_reset/recovery_email.txt'
    email_subject_template_name = 'password_reset/recovery_email_subject.txt'

    def get_site(self):
        return get_current_site(self.request)

    def create_token(self, user, token_type='email'):
        token = user.create_two_step_token(token_type=token_type)
        return token.two_step_token

    def send_email(self, user):
        context = {
            'site': self.get_site(),
            'user': user,
            'username': user.get_username(),
            'token': self.create_token(user),
            'secure': self.request.is_secure(),
        }
        body = loader.render_to_string(self.email_template_name, context).strip()
        subject = loader.render_to_string(self.email_subject_template_name,
                                          context).strip()
        html_message = loader.render_to_string(self.template_name, context).strip()
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL,
                  [user.email], fail_silently=False, html_message=html_message, )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email', None)

            if email:
                user = get_object_or_404(User, email=email)
                try:
                    self.send_email(user=user)
                except Exception as e:
                    return Response(data=_('There is a problem in send email. ') + str(e),
                                    status=status.HTTP_400_BAD_REQUEST)
                return Response(data=_('You receive a code in your email.'), status=status.HTTP_200_OK)
        return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)


class VerifyForgotPassword(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = (IsNotAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.fields['token'].required = True
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email', None)
            token = serializer.validated_data.get('token', None)
            if email:
                user = get_object_or_404(User, email=email)
            if user.is_valid_two_step_token(token, expire_duration=self.expires_duration):
                login(request=self.request, user=user)
                return Response(status=status.HTTP_200_OK)
            return Response(data=_('Invalid token'), status=status.HTTP_400_BAD_REQUEST)

    @property
    def expires_duration(self):
        return getattr(settings, 'FORGOT_PASSWORD_EXPIRE_TIME', 3600)

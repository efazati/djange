from django.contrib.auth import authenticate
from rest_framework import serializers, exceptions
from project.apps.core.models import User
from django.utils.translation import ugettext_lazy as _


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name')


class UserSerializerVersionAdmin(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'is_active')


class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})

    def _validate_phone(self, phone, password):
        user = None

        if phone and password:
            user = authenticate(phone=phone, password=password)
        else:
            msg = _('Must include "phone" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _("Couldn't found user with entered phone ")
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


#
# class TokenSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Token
#         fields = ('key',)


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username', 'first_name', 'last_name', 'password')


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    token = serializers.CharField(required=False, max_length=6)

from django.conf.urls import url

from project.apps.core.api import views

urlpatterns = [
    url(r'^auth/login/$', views.LoginView.as_view()),
    url(r'^auth/logout/$', views.LogoutView.as_view()),

    url(r'^users/registration/$', views.UserRegistration.as_view()),
    url(r'^users/profile/$', views.Profile.as_view()),
    url(r'users/forgot-password/$', views.ForgotPassword.as_view()),
    url(r'users/forgot-password/verify', views.VerifyForgotPassword.as_view()),

]


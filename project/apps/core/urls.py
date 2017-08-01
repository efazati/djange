from django.conf.urls import url
from django.contrib.auth import views as django_auth_views
from project.apps.core import views

urlpatterns = [
    url(r'^$', views.ProfileDetail.as_view(), name='profile'),
    url(r'^accounts/login/$', django_auth_views.LoginView.as_view(), name='login'),
    url(r'^accounts/logout/$', django_auth_views.LogoutView.as_view(), name='logout'),

    url(r'^accounts/password_change/$', django_auth_views.PasswordChangeView.as_view(), name='password_change'),
    url(r'^accounts/password_change/done/$', django_auth_views.PasswordChangeDoneView.as_view(),
        name='password_change_done'),

    url(r'^accounts/password_reset/$', django_auth_views.PasswordResetView.as_view(), name='password_reset'),
    url(r'^accounts/password_reset/done/$', django_auth_views.PasswordResetDoneView.as_view(),
        name='password_reset_done'),
    url(r'^accounts/reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        django_auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    url(r'^accounts/reset/done/$', django_auth_views.PasswordResetCompleteView.as_view(),
        name='password_reset_complete'),

]

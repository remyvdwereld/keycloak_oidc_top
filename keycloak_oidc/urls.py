from django.urls import include, re_path

from keycloak_oidc.views import OIDCLogoutView

urlpatterns = [
    # Change logout url, allow GET
    re_path(r'^logout/$', OIDCLogoutView.as_view(), name='oidc_logout'),
    re_path(r'^', include('mozilla_django_oidc.urls')),
]

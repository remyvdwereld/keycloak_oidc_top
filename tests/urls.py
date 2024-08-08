from django.urls import include, re_path

urlpatterns = [
    re_path(r'^oidc/', include('keycloak_oidc.urls')),
]
